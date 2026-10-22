#!/usr/bin/env python3
"""SSH over iMessage: a reliable, authenticated byte stream carried in text messages.

Two Macs signed into Messages exchange base64 packets as ordinary messages in one
conversation. The home machine relays the stream into its own sshd; the laptop runs
this program as an OpenSSH ProxyCommand. SSH still performs host-key verification,
authentication and encryption end to end -- this transport only moves bytes, and the
relay only ever connects to the single target in its own config file.

Standard library only. Packets are read straight out of the local Messages database
(both the `text` column and `attributedBody`, because Messages stores many messages
only in the latter) and sent with `imsg` when it is installed, otherwise AppleScript.

Subcommands: init, export, import, setup, doctor, serve, proxy, connect,
install-agent, uninstall-agent.
"""
import argparse
import base64
from collections import OrderedDict, deque
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import select
import shlex
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import time

PREFIX = 'CB1 SSH1 '            # marker; coexists with other CB1-family bridges
PACKET_RE = re.compile(rb'CB1 SSH1 [A-Za-z0-9_\-=]{1,3500} [0-9a-f]{64}')
KINDS = ('O', 'D', 'E', 'A', 'P', 'R', 'N', 'X')
CHUNK = 1200                    # payload bytes per message
WINDOW = 4                      # unacknowledged packets in flight
RETRY = 20.0                    # seconds before a first retransmission
MAX_TRIES = 20
ACK_DELAY = 2.0                 # hold a bare ACK this long so data can carry it
KEEPALIVE = 120.0               # probe a silent peer after this long
PEER_TIMEOUT = 300.0            # declare the peer dead after this long
SESSION_TIMEOUT = 14400.0
CONNECT_TIMEOUT = 300.0
OPEN_FRESH = 300                # ignore OPEN packets older than this
PROBE_GRACE = 20.0              # silence after a probe before a stale session yields
OUTBOX_MAX = 1 << 16            # unsent bytes buffered out of the local socket
DEFAULT_CONFIG = Path.home() / '.config/imsg-ssh/config.json'
CHAT_DB = Path.home() / 'Library/Messages/chat.db'
# Messages stores a body in `text`, in `attributedBody`, or both, and may clear
# `text` later; SQLite's LIKE is always false for a BLOB, hence the CAST.
HAS_PACKET = ("(m.text LIKE 'CB1 SSH1 %' OR "
              "instr(CAST(m.attributedBody AS TEXT), 'CB1 SSH1 ') > 0)")
HOST_ALIAS = 'imsg-ssh-home'
AGENT_LABEL = 'com.imsg-ssh.relay'

CLIENT_KEYS = ('key', 'ssh_user', 'ssh_host_key', 'message_interval', 'host_alias')


def log(text):
    print('imsg-ssh: ' + text, file=sys.stderr, flush=True)


# --- framing ---------------------------------------------------------------

def encode(key, sid, role, kind, seq=-1, ack=-1, data=b'', timestamp=None):
    obj = [sid, role, kind, seq, ack, int(time.time() if timestamp is None else timestamp),
           base64.b64encode(data).decode()]
    raw = json.dumps(obj, separators=(',', ':')).encode()
    body = base64.urlsafe_b64encode(raw).decode()
    return PREFIX + body + ' ' + hmac.new(key, body.encode(), hashlib.sha256).hexdigest()


def decode(key, text):
    if not isinstance(text, str) or not text.startswith(PREFIX) or len(text) > 4096:
        return None
    try:
        body, mac = text[len(PREFIX):].split(' ')
        if not hmac.compare_digest(mac, hmac.new(key, body.encode(), hashlib.sha256).hexdigest()):
            return None
        sid, role, kind, seq, ack, timestamp, payload = json.loads(
            base64.b64decode(body, altchars=b'-_', validate=True))
        data = base64.b64decode(payload, validate=True)
        if (not isinstance(sid, str) or not re.fullmatch('[0-9a-f]{32}', sid)
                or role not in ('C', 'S') or kind not in KINDS
                or type(seq) is not int or type(ack) is not int or type(timestamp) is not int
                or not -1 <= seq < 2**53 or not -1 <= ack < 2**53 or len(data) > CHUNK
                or (kind != 'D' and data) or (kind in ('D', 'E') and seq < 0)):
            return None
        return dict(sid=sid, role=role, kind=kind, seq=seq, ack=ack, timestamp=timestamp, data=data)
    except (ValueError, TypeError):
        return None


class Stream:
    """Bounded sliding window with cumulative ACKs, delayed ACKs and ordered EOF."""

    def __init__(self, key, sid, role, retry=RETRY, ack_delay=0.0):
        self.key, self.sid, self.role = key, sid, role
        self.retry, self.ack_delay = retry, ack_delay
        self.max_retry = retry * 4
        self.pending = OrderedDict()
        self.buffer = {}
        self.next_send = self.next_recv = 0
        self.ack_sent = -1
        self.ack_due = False
        self.ack_since = 0.0
        self.local_eof = self.remote_eof = False
        self.bytes_in = self.bytes_out = self.packets_out = self.retries = 0

    def ready(self):
        """True when another payload can be queued."""
        return not self.local_eof and len(self.pending) < WINDOW

    def enqueue(self, data):
        if not self.ready():
            raise ValueError('stream window full or closed')
        if data is not None and not 0 < len(data) <= CHUNK:
            raise ValueError('bad data size')
        self.pending[self.next_send] = ['E' if data is None else 'D', data or b'', None, 0]
        self.next_send += 1
        self.local_eof = data is None
        self.bytes_out += len(data or b'')

    def receive(self, frame, now=0.0):
        if frame['sid'] != self.sid or frame['role'] == self.role:
            return []
        if frame['ack'] < self.next_send:
            for seq in [s for s in self.pending if s <= frame['ack']]:
                del self.pending[seq]
        if frame['kind'] not in ('D', 'E'):
            return []
        if not self.ack_due:
            # Duplicates must re-ACK too: the previous ACK may have been lost.
            self.ack_due, self.ack_since = True, now
        seq = frame['seq']
        if seq < self.next_recv or self.remote_eof:
            return []
        if seq >= self.next_recv + WINDOW:
            return []  # bound memory even for an authenticated but malfunctioning peer
        self.buffer.setdefault(seq, (frame['kind'], frame['data']))
        ready = []
        while self.next_recv in self.buffer:
            kind, data = self.buffer.pop(self.next_recv)
            self.next_recv += 1
            if kind == 'E':
                self.remote_eof = True
                self.buffer.clear()
                ready.append(None)
                break
            self.bytes_in += len(data)
            ready.append(data)
        return ready

    def packet(self, now):
        # Data carries the ACK; prefer new or due data over a standalone ACK.
        for seq, (kind, data, sent, tries) in self.pending.items():
            if sent is None or now - sent >= min(self.retry * 1.6 ** (tries - 1), self.max_retry):
                if tries >= MAX_TRIES:
                    raise TimeoutError('peer did not acknowledge %d packets' % len(self.pending))
                return encode(self.key, self.sid, self.role, kind, seq, self.next_recv - 1, data)
        if self.ack_due and (self.remote_eof or now - self.ack_since >= self.ack_delay
                             or self.next_recv - 1 - self.ack_sent >= WINDOW - 1):
            return encode(self.key, self.sid, self.role, 'A', ack=self.next_recv - 1)
        return None

    def sent(self, packet, now):
        frame = decode(self.key, packet)
        self.packets_out += 1
        self.ack_sent = frame['ack']
        self.ack_due = self.ack_sent < self.next_recv - 1
        self.ack_since = now
        item = self.pending.get(frame['seq']) if frame['kind'] in ('D', 'E') else None
        if item is not None:
            item[2], item[3] = now, item[3] + 1
            if item[3] > 1:
                self.retries += 1


# --- iMessage link ---------------------------------------------------------

def run(args, timeout=45, stdin=None):
    p = subprocess.Popen(args, stdin=subprocess.PIPE if stdin is not None else None,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                         start_new_session=True)
    try:
        out, err = p.communicate(stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.communicate()
        raise RuntimeError('%s timed out (check Messages automation permission)' % args[0])
    if p.returncode:
        raise RuntimeError(err.strip() or out.strip() or '%s failed' % args[0])
    return out


SEND_SCRIPT = '''
on run argv
  set theTarget to item 1 of argv
  set theBody to item 2 of argv
  set theKind to item 3 of argv
  tell application "Messages"
    if theKind is "chat" then
      send theBody to text chat id theTarget
    else
      send theBody to participant theTarget of (1st account whose service type = iMessage)
    end if
  end tell
end run
'''


def open_chat_db(path=CHAT_DB):
    try:
        return sqlite3.connect('file:%s?mode=ro' % path, uri=True)
    except sqlite3.Error as exc:
        raise RuntimeError('cannot open %s (%s); grant Full Disk Access to this '
                           'terminal or app, restart it and retry' % (path, exc))


def make_sender(config):
    """Return send(text). Prefers imsg; falls back to AppleScript."""
    mode = config.get('sender', 'auto')
    binary = config.get('imsg')
    if not binary or not Path(binary).exists():
        binary = shutil.which('imsg')
    if mode in ('auto', 'imsg') and binary and Path(binary).exists():
        chat = str(config['chat_id'])
        def send(text):
            run([binary, 'send', '--chat-id', chat, '--service', 'imessage',
                 '--no-sms-fallback', '--text', text])
        return send
    if mode == 'imsg':
        raise RuntimeError('sender is set to imsg but imsg is not installed')
    target = config.get('chat_guid') if config.get('chat_is_group') else config.get('handle')
    if not target:
        raise RuntimeError('AppleScript sending needs config.handle; rerun setup')
    kind = 'chat' if config.get('chat_is_group') else 'buddy'
    def send(text):
        run(['osascript', '-', target, text, kind], stdin=SEND_SCRIPT)
    return send


class MessageLink:
    """Reads packets from the Messages database, sends them as iMessages."""

    def __init__(self, config):
        self.chat_id = int(config['chat_id'])
        self.db = Path(config.get('chat_db') or CHAT_DB).expanduser()
        self.interval = float(config.get('message_interval', 1.5))
        if self.interval < .1:
            raise ValueError('message_interval must be at least 0.1 seconds')
        self.poll_seconds = float(config.get('poll_seconds', .25))
        self.idle_poll_seconds = float(config.get('idle_poll_seconds', 1.0))
        self.busy_seconds = float(config.get('busy_seconds', 60))
        self.reopen_seconds = float(config.get('reopen_seconds', 30))
        self.send_one = make_sender(config)
        self.con = open_chat_db(self.db)
        self.queue = deque()
        self.seen = OrderedDict()
        self.last_send = 0.0
        self.next_poll = 0.0
        self.cursor = self._latest_rowid()
        self.last_new = self.last_packet = time.monotonic()
        self.sends = self.reads = 0

    def _latest_rowid(self):
        row = self.con.execute("""
            SELECT MAX(m.ROWID) FROM message m
            JOIN chat_message_join j ON j.message_id = m.ROWID WHERE j.chat_id = ?
        """, (self.chat_id,)).fetchone()
        return row[0] or 0

    def _reopen(self):
        try:
            self.con.close()
        except sqlite3.Error:
            pass
        self.con = open_chat_db(self.db)
        self.last_new = time.monotonic()

    def _poll(self):
        # Cheap insurance against a read connection that has stopped seeing
        # commits (checkpointing, a replaced database file, a suspended process).
        if time.monotonic() - self.last_new > self.reopen_seconds:
            self._reopen()
        try:
            rows = self.con.execute("""
                SELECT m.ROWID, m.text, m.attributedBody FROM message m
                JOIN chat_message_join j ON j.message_id = m.ROWID
                WHERE j.chat_id = ? AND m.ROWID > ? ORDER BY m.ROWID LIMIT 500
            """, (self.chat_id, self.cursor)).fetchall()
        except sqlite3.Error as exc:
            log('Messages database read failed, reopening: %s' % exc)
            self._reopen()
            return
        if rows:
            self.last_new = time.monotonic()
        for rowid, text, blob in rows:
            self.cursor = max(self.cursor, rowid)
            packet = None
            if isinstance(text, str) and text.startswith(PREFIX):
                packet = text
            elif blob:
                # Messages often stores the body only in attributedBody.
                found = PACKET_RE.search(blob if isinstance(blob, bytes) else bytes(blob))
                if found:
                    packet = found.group(0).decode()
            if packet is None or packet in self.seen:
                continue  # a shared conversation echoes each message to both rows
            self.seen[packet] = True
            while len(self.seen) > 512:
                self.seen.popitem(last=False)
            self.reads += 1
            self.last_packet = time.monotonic()
            self.queue.append(packet)

    def receive(self, timeout=.05):
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            if self.queue:
                return self.queue.popleft()
            now = time.monotonic()
            if now >= self.next_poll:
                # Poll briskly inside a conversation, lazily while nothing is happening.
                self.next_poll = now + (self.poll_seconds
                                        if now - self.last_packet < self.busy_seconds
                                        else self.idle_poll_seconds)
                self._poll()
                if self.queue:
                    continue
                now = time.monotonic()
            if now >= deadline:
                return None
            time.sleep(min(.02, max(0.0, min(deadline, self.next_poll) - now)))

    def send(self, line):
        wait = self.last_send + self.interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        try:
            self.send_one(line)
            self.sends += 1
        except RuntimeError as exc:
            # Some sends complete even when the tool's confirmation times out; a
            # retransmission is harmless because sequence numbers deduplicate.
            log('send unconfirmed, will retry: %s' % str(exc)[:200])
        self.last_send = time.monotonic()

    def close(self):
        try:
            self.con.close()
        except sqlite3.Error:
            pass


class SocketLink:
    """Newline-framed local test link. Never used by the iMessage service."""

    def __init__(self, sock):
        self.sock = sock
        self.buffer = b''

    def send(self, text):
        self.sock.sendall(text.encode() + b'\n')

    def receive(self, timeout=.05):
        if b'\n' not in self.buffer and select.select([self.sock], [], [], timeout)[0]:
            data = self.sock.recv(8192)
            if not data:
                raise EOFError('test link closed')
            self.buffer += data
        if b'\n' in self.buffer:
            line, self.buffer = self.buffer.split(b'\n', 1)
            return line.decode()
        return None

    def close(self):
        self.sock.close()


# --- session ---------------------------------------------------------------

def write_all(fd, data):
    view = memoryview(data)
    while view:
        size = os.write(fd, view)
        if size <= 0:
            raise BrokenPipeError('local stream closed')
        view = view[size:]


class Preempt(Exception):
    """The relay abandoned a stale session in favour of a newer OPEN."""

    def __init__(self, frame):
        super().__init__('stale session preempted')
        self.frame = frame


def session(link, key, sid, role, source, sink, close_sink, config):
    """Pump bytes between a local fd and the link until either side finishes.

    Returns normally when the session ends; raises Preempt (relay only) when a
    newer client should take over.
    """
    stream = Stream(key, sid, role, float(config.get('retry_seconds', RETRY)),
                    float(config.get('ack_delay', ACK_DELAY)))
    keepalive = float(config.get('keepalive_seconds', KEEPALIVE))
    peer_timeout = float(config.get('peer_timeout', PEER_TIMEOUT))
    session_timeout = float(config.get('session_timeout', SESSION_TIMEOUT))
    probe_grace = float(config.get('probe_grace', PROBE_GRACE))
    parent = os.getppid() if role == 'C' else None
    outbox = bytearray()
    source_eof = sink_closed = False
    started = last_peer = time.monotonic()
    last_probe = probed_at = 0.0
    reset = set()
    try:
        while True:
            now = time.monotonic()
            if now - started > session_timeout:
                raise TimeoutError('session duration limit reached')
            if now - last_peer > peer_timeout:
                raise TimeoutError('no authenticated peer traffic for %ds' % peer_timeout)
            if parent is not None and os.getppid() != parent:
                log('ssh exited; releasing the relay')
                return

            text = link.receive(.03)
            frame = decode(key, text) if text else None
            if frame and frame['role'] != role:
                if frame['sid'] != sid:
                    if role != 'S' or frame['sid'] in reset:
                        continue
                    if (frame['kind'] == 'O'
                            and abs(time.time() - frame['timestamp']) < OPEN_FRESH):
                        # A newer client is asking. Hand over once this side is
                        # finished with its socket, or once this session's peer has
                        # stayed silent through a full probe.
                        if source_eof or (probed_at and last_peer < probed_at
                                          and now - probed_at >= probe_grace):
                            raise Preempt(frame)
                        link.send(encode(key, frame['sid'], 'S', 'R'))
                        if not probed_at or last_peer >= probed_at:
                            link.send(encode(key, sid, 'S', 'P'))
                            probed_at = last_probe = time.monotonic()
                    else:
                        # A client from an abandoned session: let it fail now
                        # rather than wait out its own peer timeout.
                        reset.add(frame['sid'])
                        link.send(encode(key, frame['sid'], 'S', 'R'))
                    continue
                last_peer = now
                if frame['kind'] in ('R', 'N'):
                    raise ConnectionResetError('peer reset the session')
                if frame['kind'] == 'X':
                    return
                if frame['kind'] == 'P':
                    stream.ack_due, stream.ack_since = True, 0.0  # answer on this pass
                elif frame['kind'] == 'O' and role == 'S':
                    link.send(encode(key, sid, 'S', 'O'))
                for data in stream.receive(frame, now):
                    if data is None:
                        if not sink_closed:
                            sink_closed = True
                            close_sink()
                    else:
                        write_all(sink, data)

            # Read the local side independently of the send window: a full window
            # must never hide the fact that the local socket has closed.
            if not source_eof and len(outbox) < OUTBOX_MAX and select.select([source], [], [], 0)[0]:
                try:
                    data = os.read(source, CHUNK * 8)
                except OSError:
                    data = b''
                if data:
                    outbox += data
                else:
                    source_eof = True
            while stream.ready() and (outbox or source_eof):
                if outbox:
                    stream.enqueue(bytes(outbox[:CHUNK]))
                    del outbox[:CHUNK]
                else:
                    stream.enqueue(None)

            now = time.monotonic()
            packet = stream.packet(now)
            if packet:
                link.send(packet)
                stream.sent(packet, now)
            elif now - max(last_peer, last_probe) > keepalive:
                link.send(encode(key, sid, role, 'P', ack=stream.next_recv - 1))
                last_probe = time.monotonic()

            if stream.local_eof and not stream.pending:
                return  # everything we had was delivered and acknowledged
            if role == 'C' and stream.remote_eof and not stream.ack_due:
                return  # sshd closed and our final ACK is out; ssh is finished
    finally:
        log('session %s moved %d bytes in / %d out in %d messages%s'
            % (sid[:8], stream.bytes_in, stream.bytes_out, stream.packets_out,
               ', %d retransmitted' % stream.retries if stream.retries else ''))


def open_session(link, key, config):
    """Client side: ask the relay for a session and return its id."""
    sid = secrets.token_hex(16)
    retry = float(config.get('retry_seconds', RETRY))
    deadline = time.monotonic() + float(config.get('connect_timeout', CONNECT_TIMEOUT))
    next_send, busy = 0.0, 0
    while time.monotonic() < deadline:
        if time.monotonic() >= next_send:
            link.send(encode(key, sid, 'C', 'O'))
            next_send = time.monotonic() + (max(10.0, retry / 2) if busy else retry)
        text = link.receive(.1)
        frame = decode(key, text) if text else None
        if not frame or frame['sid'] != sid or frame['role'] != 'S':
            continue
        if frame['kind'] == 'N':
            raise RuntimeError('relay refused: it could not reach its configured sshd')
        if frame['kind'] == 'R':
            busy += 1
            if busy == 1:
                log('relay is busy with another session; retrying until it yields')
            continue
        if frame['kind'] == 'O':
            return sid
    raise TimeoutError('relay did not answer; check that the relay is running, that '
                       'both Macs use the same conversation and shared key, and that '
                       'their clocks agree to within five minutes')


def serve(link, key, config, once=False):
    pending_open = None
    completed = OrderedDict()  # do not reopen a finished session on a replayed OPEN
    target = (config.get('target_host', '127.0.0.1'), int(config.get('target_port', 22)))
    log('relay ready for %s:%d (one session at a time)' % target)
    while True:
        frame, pending_open = pending_open, None
        if frame is None:
            text = link.receive(.5)
            frame = decode(key, text) if text else None
        if (not frame or frame['role'] != 'C' or frame['kind'] != 'O'
                or abs(time.time() - frame['timestamp']) > OPEN_FRESH
                or frame['sid'] in completed):
            continue
        sid = frame['sid']
        sock = None
        try:
            sock = socket.create_connection(target, timeout=10)
        except OSError as exc:
            log('cannot reach %s:%d: %s' % (target[0], target[1], exc))
            link.send(encode(key, sid, 'S', 'N'))
            completed[sid] = time.time()   # a duplicate OPEN must not retry it
            continue
        try:
            sock.settimeout(None)
            link.send(encode(key, sid, 'S', 'O'))
            log('session %s connected' % sid[:8])
            session(link, key, sid, 'S', sock.fileno(), sock.fileno(),
                    lambda: sock.shutdown(socket.SHUT_WR), config)
            log('session %s closed' % sid[:8])
        except Preempt as exc:
            pending_open = exc.frame
            log('session %s preempted by %s' % (sid[:8], exc.frame['sid'][:8]))
        except (OSError, RuntimeError, TimeoutError) as exc:
            log('session %s ended: %s' % (sid[:8], exc))
            link.send(encode(key, sid, 'S', 'R'))
        finally:
            sock.close()
        completed[sid] = time.time()
        while len(completed) > 1000:
            completed.popitem(last=False)
        if once and pending_open is None:
            return


# --- configuration ---------------------------------------------------------

def load_config(path):
    path = Path(path).expanduser()
    if not path.exists():
        raise RuntimeError('no config at %s; run "imsg_ssh.py init" first' % path)
    cfg = json.loads(path.read_text())
    key = bytes.fromhex(cfg['key'])
    if len(key) != 32:
        raise ValueError('config key must be 32 random bytes encoded as hex')
    if not cfg.get('chat_id'):
        raise RuntimeError('config has no chat_id; run "imsg_ssh.py setup"')
    return cfg, key


def save_config(path, cfg):
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cfg, indent=2, sort_keys=True) + '\n')
    path.chmod(0o600)


def list_chats(limit=40):
    con = open_chat_db()
    try:
        return con.execute("""
            SELECT c.ROWID, c.guid, c.chat_identifier, COALESCE(c.display_name, ''),
                   COUNT(*) AS messages,
                   datetime(MAX(m.date)/1000000000 + 978307200, 'unixepoch', 'localtime')
            FROM chat c
            JOIN chat_message_join j ON j.chat_id = c.ROWID
            JOIN message m ON m.ROWID = j.message_id
            GROUP BY c.ROWID ORDER BY MAX(m.date) DESC LIMIT ?
        """, (limit,)).fetchall()
    finally:
        con.close()


def bridge_chats():
    """Chats on this Mac that already carry imsg-ssh packets, newest first."""
    con = open_chat_db()
    try:
        rows = con.execute("""
            SELECT c.ROWID, c.guid, c.chat_identifier, COUNT(*), MAX(m.date)
            FROM chat c
            JOIN chat_message_join j ON j.chat_id = c.ROWID
            JOIN message m ON m.ROWID = j.message_id
            WHERE %s
            GROUP BY c.ROWID ORDER BY MAX(m.date) DESC
        """ % HAS_PACKET).fetchall()
    finally:
        con.close()
    return rows


def chat_details(chat_id):
    con = open_chat_db()
    try:
        row = con.execute('SELECT guid, chat_identifier, COALESCE(display_name, \'\') '
                          'FROM chat WHERE ROWID = ?', (chat_id,)).fetchone()
    finally:
        con.close()
    if not row:
        raise RuntimeError('this Mac has no chat with row id %d' % chat_id)
    guid, identifier, name = row
    return dict(chat_id=chat_id, chat_guid=guid, handle=identifier, chat_name=name,
                chat_is_group=bool(identifier.startswith('chat') and ';+;' in guid))


def host_ssh_key():
    """This Mac's sshd public host key, as the 'type base64' pair known_hosts wants."""
    for name in ('ssh_host_ed25519_key.pub', 'ssh_host_rsa_key.pub'):
        path = Path('/etc/ssh') / name
        if path.exists():
            fields = path.read_text().split()
            if len(fields) >= 2:
                return fields[0] + ' ' + fields[1]
    return ''


def cmd_init(args):
    path = Path(args.config).expanduser()
    if path.exists() and not args.force:
        raise RuntimeError('refusing to overwrite %s (use --force)' % path)
    cfg = dict(key=secrets.token_hex(32), chat_id=None, message_interval=1.5,
               host_alias=HOST_ALIAS)
    if args.role == 'home':
        cfg.update(target_host='127.0.0.1', target_port=22,
                   ssh_user=os.environ.get('USER', ''), ssh_host_key=host_ssh_key())
    save_config(path, cfg)
    log('wrote %s with a fresh 256-bit shared key' % path)
    log('next: imsg_ssh.py setup --config %s' % path)


def cmd_export(args):
    cfg, _ = load_config(args.config)
    bundle = {k: cfg[k] for k in CLIENT_KEYS if cfg.get(k)}
    bundle['ssh_user'] = cfg.get('ssh_user') or os.environ.get('USER', '')
    bundle['ssh_host_key'] = cfg.get('ssh_host_key') or host_ssh_key()
    if not bundle['ssh_host_key']:
        bundle.pop('ssh_host_key')
        log('WARNING no sshd host key found in /etc/ssh; is Remote Login enabled?')
        log('without it the laptop cannot pin this Mac and will refuse to connect')
    blob = base64.urlsafe_b64encode(json.dumps(bundle, sort_keys=True).encode()).decode()
    print(blob)
    log('paste that line into the laptop\'s: imsg_ssh.py import <bundle>')
    log('it contains the shared transport key: treat it like a password')


def cmd_import(args):
    path = Path(args.config).expanduser()
    bundle = json.loads(base64.urlsafe_b64decode(args.bundle.strip().encode()))
    cfg = json.loads(path.read_text()) if path.exists() else {}
    cfg.update(bundle)
    cfg.setdefault('chat_id', None)
    cfg.setdefault('host_alias', HOST_ALIAS)
    save_config(path, cfg)
    if cfg.get('ssh_host_key'):
        hosts = path.parent / 'known_hosts'
        hosts.write_text('%s %s\n' % (cfg['host_alias'], cfg['ssh_host_key']))
        hosts.chmod(0o600)
        log('pinned the home host key in %s' % hosts)
    log('wrote %s; next: imsg_ssh.py setup --config %s' % (path, path))


def cmd_setup(args):
    path = Path(args.config).expanduser()
    cfg = json.loads(path.read_text()) if path.exists() else {}
    if 'key' not in cfg:
        raise RuntimeError('run init (home) or import (laptop) before setup')
    chat_id = args.chat_id
    if chat_id is None:
        found = bridge_chats()
        if found:
            print('Conversations on this Mac that already carry imsg-ssh packets:')
            for rowid, _guid, ident, packets, _ in found:
                print('  chat %-6d %-34s %d packets' % (rowid, ident, packets))
            chat_id = found[0][0]
            print('\nUsing chat %d (most recent packet traffic).' % chat_id)
        else:
            print('Recent conversations on this Mac:')
            for rowid, _guid, ident, name, count, last in list_chats():
                print('  chat %-6d %-34s %-22s %6d msgs  %s'
                      % (rowid, ident, name[:22], count, last))
            print('\nPick the conversation both Macs share. Row ids are per-Mac, so the')
            print('other Mac\'s number will not work here.')
            chat_id = int(input('chat id: ').strip())
    cfg.update(chat_details(int(chat_id)))
    found = shutil.which('imsg')
    if found and not Path(cfg.get('imsg') or '/nonexistent').exists():
        cfg['imsg'] = found      # a stored path can go stale across upgrades
    save_config(path, cfg)
    log('configured chat %d (%s)' % (cfg['chat_id'], cfg['handle']))
    return cmd_doctor(args)


def cmd_doctor(args):
    cfg, key = load_config(args.config)
    con = open_chat_db(Path(cfg.get('chat_db') or CHAT_DB))
    rows = con.execute("""
        SELECT COUNT(*), SUM(CASE WHEN m.text LIKE 'CB1 SSH1 %%' THEN 1 ELSE 0 END)
        FROM message m JOIN chat_message_join j ON j.message_id = m.ROWID
        WHERE j.chat_id = ? AND %s
    """ % HAS_PACKET, (cfg['chat_id'],)).fetchone()
    total = con.execute('SELECT COUNT(*) FROM chat_message_join WHERE chat_id = ?',
                        (cfg['chat_id'],)).fetchone()[0]
    con.close()
    log('Messages database readable; chat %d has %d messages' % (cfg['chat_id'], total))
    log('%d imsg-ssh packets in history (%d of them visible in the text column)'
        % (rows[0] or 0, rows[1] or 0))
    make_sender(cfg)
    log('sender ready: %s' % ('imsg' if cfg.get('imsg') or shutil.which('imsg')
                              else 'AppleScript'))
    log('shared key present (%d bits)' % (len(key) * 8))
    if cfg.get('target_host'):
        try:
            socket.create_connection((cfg['target_host'], int(cfg['target_port'])),
                                     timeout=5).close()
            log('sshd reachable at %s:%s' % (cfg['target_host'], cfg['target_port']))
        except OSError as exc:
            log('WARNING cannot reach %s:%s (%s); enable Remote Login'
                % (cfg['target_host'], cfg['target_port'], exc))
    log('doctor cannot prove send permission or cross-device delivery: run a real connect')


def cmd_connect(args):
    cfg, _ = load_config(args.config)
    config_path = str(Path(args.config).expanduser())
    proxy = shlex.join([sys.executable, str(Path(__file__).resolve()), 'proxy',
                        '--config', config_path])
    hosts = Path(config_path).parent / 'known_hosts'
    alias = cfg.get('host_alias', HOST_ALIAS)
    command = ['/usr/bin/ssh', '-C', '-o', 'ProxyCommand=' + proxy,
               '-o', 'HostKeyAlias=' + alias,
               '-o', 'UserKnownHostsFile=' + str(hosts),
               '-o', 'StrictHostKeyChecking=yes',
               '-o', 'ConnectTimeout=300',
               '-o', 'ServerAliveInterval=90', '-o', 'ServerAliveCountMax=6']
    if args.tty:
        command.append('-t')
    user = cfg.get('ssh_user') or os.environ.get('USER', '')
    command.append('%s@%s' % (user, alias) if user else alias)
    command += args.command
    os.execv(command[0], command)


def agent_plist_path(label):
    return Path.home() / 'Library/LaunchAgents' / (label + '.plist')


def cmd_install_agent(args):
    config_path = str(Path(args.config).expanduser())
    load_config(config_path)
    logs = Path.home() / 'Library/Logs/imsg-ssh.log'
    plist = dict(Label=args.label, RunAtLoad=True, KeepAlive=True, ThrottleInterval=30,
                 ProgramArguments=[sys.executable, str(Path(__file__).resolve()), 'serve',
                                   '--config', config_path],
                 WorkingDirectory=str(Path(__file__).resolve().parent),
                 EnvironmentVariables={'PATH': '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'},
                 StandardOutPath=str(logs), StandardErrorPath=str(logs))
    path = agent_plist_path(args.label)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(plist))
    domain = 'gui/%d' % os.getuid()
    subprocess.run(['launchctl', 'bootout', domain + '/' + args.label],
                   capture_output=True)
    subprocess.run(['launchctl', 'bootstrap', domain, str(path)], check=True)
    log('installed %s; logs at %s' % (path, logs))
    log('the relay needs this Mac awake, signed into Messages, with Remote Login on')


def cmd_uninstall_agent(args):
    subprocess.run(['launchctl', 'bootout', 'gui/%d/%s' % (os.getuid(), args.label)],
                   capture_output=True)
    agent_plist_path(args.label).unlink(missing_ok=True)
    log('removed %s' % agent_plist_path(args.label))


def cmd_relay(args, mode):
    cfg, key = load_config(args.config)
    if args.chat_id is not None:
        cfg['chat_id'] = args.chat_id
    lock = None
    if mode == 'serve':
        lock = Path(args.config).expanduser().with_suffix('.relay.lock').open('a')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('another relay is already running for this config')
    listener = None
    if args.test_socket:
        sock = socket.socket(socket.AF_UNIX)
        if mode == 'serve':
            listener = sock
            listener.bind(args.test_socket)
            listener.listen(1)
            sock, _ = listener.accept()
        else:
            sock.connect(args.test_socket)
        link = SocketLink(sock)
    else:
        link = MessageLink(cfg)
    sid = None
    try:
        if mode == 'serve':
            serve(link, key, cfg, args.once)
        else:
            log('opening SSH over iMessage; the handshake takes a few minutes')
            sid = open_session(link, key, cfg)
            session(link, key, sid, 'C', sys.stdin.fileno(), sys.stdout.fileno(),
                    lambda: os.close(sys.stdout.fileno()), cfg)
    finally:
        if sid:
            # Free the relay immediately instead of leaving it to time out.
            for _ in range(2):
                try:
                    link.send(encode(key, sid, 'C', 'X'))
                    break
                except (OSError, RuntimeError):
                    pass
        link.close()
        if listener:
            listener.close()
            Path(args.test_socket).unlink(missing_ok=True)


def main(argv=None):
    # --config is accepted both before and after the subcommand; SUPPRESS keeps the
    # subparser's copy from overwriting a value given earlier on the line.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--config', default=argparse.SUPPRESS,
                        help='config file (default: %s)' % DEFAULT_CONFIG)
    parser = argparse.ArgumentParser(prog='imsg_ssh.py', parents=[common],
                                     description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest='mode', required=True, metavar='subcommand')

    def add(name, helptext):
        return sub.add_parser(name, parents=[common], help=helptext)

    p = add('init', 'create a config with a fresh shared key')
    p.add_argument('--role', choices=['home', 'laptop'], default='home')
    p.add_argument('--force', action='store_true')
    add('export', 'print a bundle to carry to the laptop')
    p = add('import', 'load a bundle produced by export')
    p.add_argument('bundle')
    p = add('setup', "choose this Mac's chat row id")
    p.add_argument('--chat-id', type=int)
    add('doctor', 'check database access, sender and sshd')
    p = add('connect', 'ssh home over iMessage')
    p.add_argument('--tty', action='store_true', help='allocate a TTY (for tmux)')
    p.add_argument('command', nargs=argparse.REMAINDER)
    p = add('install-agent', 'run the relay as a LaunchAgent')
    p.add_argument('--label', default=AGENT_LABEL)
    p = add('uninstall-agent', 'remove the LaunchAgent')
    p.add_argument('--label', default=AGENT_LABEL)
    for name, helptext in (('serve', 'run the home relay'),
                           ('proxy', 'OpenSSH ProxyCommand (used by connect)')):
        p = add(name, helptext)
        p.add_argument('--chat-id', type=int)
        p.add_argument('--test-socket', help='local transport test only')
        p.add_argument('--once', action='store_true')

    args = parser.parse_args(argv)
    args.config = getattr(args, 'config', None) or str(DEFAULT_CONFIG)
    os.umask(0o077)
    handlers = {'init': cmd_init, 'export': cmd_export, 'import': cmd_import,
                'setup': cmd_setup, 'doctor': cmd_doctor, 'connect': cmd_connect,
                'install-agent': cmd_install_agent, 'uninstall-agent': cmd_uninstall_agent}
    if args.mode in handlers:
        return handlers[args.mode](args)
    return cmd_relay(args, args.mode)


if __name__ == '__main__':
    def terminate(signum, frame):
        raise KeyboardInterrupt()
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, terminate)
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except (RuntimeError, ValueError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        log(str(exc))
        sys.exit(1)
