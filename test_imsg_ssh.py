"""Tests for the imsg-ssh transport.

The protocol tests run offline. The fake-wire tests exercise the real relay and
proxy session loops against a stand-in for Messages and a stand-in for sshd, so
window stalls, close detection and session handover are covered without sending
a single iMessage. Set IMSG_SSH_INTEGRATION=1 to also drive real OpenSSH.
"""
import json
import os
from pathlib import Path
import random
import secrets
import shlex
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections import deque

import imsg_ssh as p


def fast_config(**extra):
    cfg = dict(retry_seconds=.4, ack_delay=0, probe_grace=.5, peer_timeout=6,
               keepalive_seconds=2, connect_timeout=8, session_timeout=60)
    cfg.update(extra)
    return cfg


class Wire:
    """A shared conversation: every message reaches both ends, including its sender."""

    def __init__(self):
        self.lock = threading.Lock()
        self.ends = []
        self.sent = 0

    def end(self):
        with self.lock:
            queue = deque()
            self.ends.append(queue)
        return WireEnd(self, queue)


class WireEnd:
    def __init__(self, wire, queue):
        self.wire, self.queue = wire, queue

    def send(self, text):
        with self.wire.lock:
            self.wire.sent += 1
            for queue in self.wire.ends:
                queue.append(text)

    def receive(self, timeout=.05):
        deadline = time.monotonic() + timeout
        while True:
            with self.wire.lock:
                if self.queue:
                    return self.queue.popleft()
            if time.monotonic() >= deadline:
                return None
            time.sleep(.002)

    def close(self):
        pass


class FakeTarget:
    """Stands in for sshd: optionally greets, optionally echoes, then may close."""

    def __init__(self, greeting=b'', echo=False, close_after_greeting=False):
        self.stop = threading.Event()
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.received = bytearray()
        self.thread = threading.Thread(target=self._run, args=(greeting, echo,
                                                               close_after_greeting),
                                       daemon=True)
        self.thread.start()

    def _run(self, greeting, echo, close_after_greeting):
        try:
            sock, _ = self.listener.accept()
        except OSError:
            return
        with sock:
            if greeting:
                sock.sendall(greeting)
            if close_after_greeting:
                sock.shutdown(socket.SHUT_WR)   # EOF to the relay, socket still open
            while not self.stop.is_set():
                try:
                    data = sock.recv(4096)
                except OSError:
                    break
                if not data:
                    break
                self.received += data
                if echo:
                    sock.sendall(data.upper())

    def close(self):
        self.stop.set()
        self.listener.close()


class FramingTests(unittest.TestCase):
    def test_authentication_and_rejection(self):
        key, sid = secrets.token_bytes(32), secrets.token_hex(16)
        line = p.encode(key, sid, 'C', 'D', 0, -1, b'binary\x00\xff')
        self.assertEqual(p.decode(key, line)['data'], b'binary\x00\xff')
        self.assertIsNone(p.decode(secrets.token_bytes(32), line), 'wrong key accepted')
        flipped = line[:-1] + ('0' if line[-1] != '0' else '1')
        self.assertIsNone(p.decode(key, flipped), 'tampered mac accepted')
        self.assertIsNone(p.decode(key, line.replace('CB1 SSH1', 'CB1 WEB1')))
        self.assertIsNone(p.decode(key, 'hello from a human'))
        self.assertIsNone(p.decode(key, None))
        self.assertTrue(line.startswith(p.PREFIX))
        self.assertLess(len(p.encode(key, sid, 'C', 'D', 0, -1, os.urandom(p.CHUNK))), 4096)

    def test_structural_validation(self):
        key, sid = secrets.token_bytes(32), secrets.token_hex(16)
        self.assertIsNone(p.decode(key, p.encode(key, sid, 'C', 'Z')), 'unknown kind')
        self.assertIsNone(p.decode(key, p.encode(key, 'nothex', 'C', 'A')))
        self.assertIsNone(p.decode(key, p.encode(key, sid, 'Q', 'A')), 'unknown role')
        self.assertIsNone(p.decode(key, p.encode(key, sid, 'C', 'A', data=b'x')),
                          'payload on a non-data packet')
        self.assertIsNone(p.decode(key, p.encode(key, sid, 'C', 'D', -1, data=b'x')))
        self.assertIsNotNone(p.decode(key, p.encode(key, sid, 'S', 'P')))

    def test_packet_regex_matches_what_encode_produces(self):
        key, sid = secrets.token_bytes(32), secrets.token_hex(16)
        line = p.encode(key, sid, 'S', 'D', 7, 3, os.urandom(p.CHUNK))
        blob = b'\x04\x0bstreamtyped\x81\xe8\x03' + line.encode() + b'\x00\x86\x84'
        found = p.PACKET_RE.search(blob)
        self.assertIsNotNone(found, 'packet not recoverable from an attributedBody blob')
        self.assertEqual(found.group(0).decode(), line)


class StreamTests(unittest.TestCase):
    def test_bidirectional_loss_reorder_duplicate_and_eof(self):
        for seed in range(8):
            rng = random.Random(seed)
            key, sid = secrets.token_bytes(32), secrets.token_hex(16)
            streams = [p.Stream(key, sid, role, retry=.3) for role in ('C', 'S')]
            data = [rng.randbytes(17000), rng.randbytes(23000)]
            chunks = [[d[i:i + p.CHUNK] for i in range(0, len(d), p.CHUNK)] + [None]
                      for d in data]
            output, transit = [[], []], []
            for tick in range(10000):
                now = tick * .05
                for i, stream in enumerate(streams):
                    while chunks[i] and stream.ready():
                        stream.enqueue(chunks[i].pop(0))
                    packet = stream.packet(now)
                    if packet:
                        stream.sent(packet, now)
                        # Self echo, loss, duplication and reordering all happen.
                        self.assertEqual(stream.receive(p.decode(key, packet), now), [])
                        if rng.random() > .25:
                            transit.append((1 - i, packet))
                            if rng.random() < .2:
                                transit.append((1 - i, packet))
                rng.shuffle(transit)
                if transit:
                    dest, line = transit.pop()
                    output[dest].extend(streams[dest].receive(p.decode(key, line), now))
                if all(s.remote_eof and not s.pending for s in streams):
                    break
            else:
                self.fail('transfer did not converge, seed %d' % seed)
            for i in range(2):
                self.assertEqual(output[i][-1], None, 'missing EOF')
                self.assertEqual(b''.join(output[i][:-1]), data[1 - i])

    def test_receive_window_bounded_and_foreign_session_ignored(self):
        key, sid = secrets.token_bytes(32), secrets.token_hex(16)
        stream = p.Stream(key, sid, 'S')
        for seq in range(100, 200):
            stream.receive(p.decode(key, p.encode(key, sid, 'C', 'D', seq, data=b'x')))
        self.assertFalse(stream.buffer, 'out-of-window data was buffered')
        other = p.encode(key, secrets.token_hex(16), 'C', 'D', 0, data=b'x')
        self.assertEqual(stream.receive(p.decode(key, other)), [])
        self.assertEqual(stream.receive(p.decode(key, p.encode(key, sid, 'S', 'D', 0,
                                                               data=b'x'))), [],
                         'accepted a packet from its own role')

    def test_retry_budget_is_finite_with_backoff(self):
        stream = p.Stream(secrets.token_bytes(32), secrets.token_hex(16), 'C', retry=1)
        stream.enqueue(b'hello')
        now = 0.0
        for _ in range(p.MAX_TRIES):
            packet = stream.packet(now)
            self.assertIsNotNone(packet, 'gave up retransmitting too early')
            stream.sent(packet, now)
            now += stream.max_retry
        with self.assertRaises(TimeoutError):
            stream.packet(now)

    def test_backoff_spaces_retransmissions_out(self):
        stream = p.Stream(secrets.token_bytes(32), secrets.token_hex(16), 'C', retry=1)
        stream.enqueue(b'hello')
        stream.sent(stream.packet(0), 0)
        self.assertIsNone(stream.packet(.9), 'retransmitted before the retry interval')
        stream.sent(stream.packet(1.0), 1.0)          # first retry, one interval later
        self.assertIsNone(stream.packet(2.2), 'second retry ignored the backoff')
        self.assertIsNotNone(stream.packet(2.7), 'second retry never happened')

    def test_bare_acks_wait_for_data_to_carry_them(self):
        key, sid = secrets.token_bytes(32), secrets.token_hex(16)
        stream = p.Stream(key, sid, 'S', retry=10, ack_delay=2)
        stream.receive(p.decode(key, p.encode(key, sid, 'C', 'D', 0, data=b'x')), now=0)
        self.assertIsNone(stream.packet(1), 'sent a bare ACK instead of waiting')
        stream.enqueue(b'output')
        packet = stream.packet(1)
        frame = p.decode(key, packet)
        self.assertEqual((frame['kind'], frame['ack']), ('D', 0),
                         'data packet did not carry the pending ACK')
        stream.sent(packet, 1)
        self.assertFalse(stream.ack_due, 'ACK still outstanding after data carried it')

    def test_bare_ack_is_sent_when_nothing_carries_it(self):
        key, sid = secrets.token_bytes(32), secrets.token_hex(16)
        stream = p.Stream(key, sid, 'S', retry=10, ack_delay=2)
        stream.receive(p.decode(key, p.encode(key, sid, 'C', 'D', 0, data=b'x')), now=0)
        self.assertEqual(p.decode(key, stream.packet(2.5))['kind'], 'A')

    def test_ack_is_immediate_when_the_peer_window_would_stall(self):
        key, sid = secrets.token_bytes(32), secrets.token_hex(16)
        stream = p.Stream(key, sid, 'S', retry=10, ack_delay=60)
        for seq in range(p.WINDOW - 1):
            stream.receive(p.decode(key, p.encode(key, sid, 'C', 'D', seq, data=b'x')), now=0)
        self.assertEqual(p.decode(key, stream.packet(0))['kind'], 'A',
                         'held an ACK while the peer window filled')

    def test_eof_is_acknowledged_immediately(self):
        key, sid = secrets.token_bytes(32), secrets.token_hex(16)
        stream = p.Stream(key, sid, 'S', retry=10, ack_delay=60)
        stream.receive(p.decode(key, p.encode(key, sid, 'C', 'E', 0)), now=0)
        self.assertEqual(p.decode(key, stream.packet(0))['kind'], 'A')


class MessageDatabaseTests(unittest.TestCase):
    """Messages stores bodies in `text`, in `attributedBody`, or both."""

    def make_db(self, rows, chat_id=1):
        path = Path(self.tmp.name) / 'chat.db'
        con = sqlite3.connect(path)
        con.executescript("""
            CREATE TABLE message (ROWID INTEGER PRIMARY KEY, text TEXT,
                                  attributedBody BLOB, date INTEGER, is_from_me INTEGER);
            CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER);
        """)
        for i, (text, blob) in enumerate(rows, start=1):
            con.execute('INSERT INTO message (ROWID, text, attributedBody, date, is_from_me)'
                        ' VALUES (?,?,?,?,0)', (i, text, blob, i))
            con.execute('INSERT INTO chat_message_join VALUES (?,?)', (chat_id, i))
        con.commit()
        con.close()
        return path

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='imsg-ssh-test-')
        self.addCleanup(self.tmp.cleanup)
        self.key = secrets.token_bytes(32)
        self.sid = secrets.token_hex(16)

    def link_for(self, path):
        link = p.MessageLink(dict(chat_id=1, chat_db=str(path), sender='applescript',
                                  handle='someone@example.com', message_interval=.1,
                                  poll_seconds=0))
        self.addCleanup(link.close)
        return link

    def drain(self, link, expect, timeout=2):
        got, deadline = [], time.monotonic() + timeout
        while len(got) < expect and time.monotonic() < deadline:
            text = link.receive(.05)
            if text:
                got.append(text)
        return got

    def test_reads_packets_from_text_and_from_attributed_body(self):
        from_text = p.encode(self.key, self.sid, 'S', 'D', 0, -1, b'in the text column')
        from_blob = p.encode(self.key, self.sid, 'S', 'D', 1, -1, b'only in attributedBody')
        path = self.make_db([('a normal human message', None)])
        link = self.link_for(path)  # opens with a cursor past existing history
        con = sqlite3.connect(path)
        con.execute('INSERT INTO message (ROWID, text, attributedBody, date, is_from_me)'
                    ' VALUES (2,?,NULL,2,0)', (from_text,))
        # The body Messages actually stores for many messages: text empty, bytes only.
        con.execute('INSERT INTO message (ROWID, text, attributedBody, date, is_from_me)'
                    ' VALUES (3,"",?,3,0)',
                    (b'\x04\x0bstreamtyped\x81\xe8\x03' + from_blob.encode() + b'\x00\x86',))
        con.execute('INSERT INTO chat_message_join VALUES (1,2),(1,3)')
        con.commit()
        con.close()
        got = self.drain(link, 2)
        self.assertEqual(got, [from_text, from_blob])
        self.assertEqual([p.decode(self.key, t)['data'] for t in got],
                         [b'in the text column', b'only in attributedBody'])

    def test_history_before_startup_is_not_replayed(self):
        old = p.encode(self.key, self.sid, 'S', 'D', 0, -1, b'yesterday')
        link = self.link_for(self.make_db([(old, None)]))
        self.assertEqual(self.drain(link, 1, timeout=.3), [],
                         'replayed a packet from before startup')

    def test_duplicate_rows_are_delivered_once(self):
        packet = p.encode(self.key, self.sid, 'S', 'A', ack=4)
        path = self.make_db([('seed', None)])
        link = self.link_for(path)
        con = sqlite3.connect(path)
        # A conversation with yourself stores both a sent and a received copy.
        for rowid in (2, 3):
            con.execute('INSERT INTO message (ROWID, text, attributedBody, date, is_from_me)'
                        ' VALUES (?,?,NULL,?,0)', (rowid, packet, rowid))
            con.execute('INSERT INTO chat_message_join VALUES (1,?)', (rowid,))
        con.commit()
        con.close()
        self.assertEqual(self.drain(link, 2, timeout=.5), [packet],
                         'echoed copy was delivered twice')

    def test_other_conversations_are_ignored(self):
        packet = p.encode(self.key, self.sid, 'S', 'A', ack=1)
        path = self.make_db([('seed', None)])
        link = self.link_for(path)
        con = sqlite3.connect(path)
        con.execute('INSERT INTO message (ROWID, text, attributedBody, date, is_from_me)'
                    ' VALUES (2,?,NULL,2,0)', (packet,))
        con.execute('INSERT INTO chat_message_join VALUES (99,2)')
        con.commit()
        con.close()
        self.assertEqual(self.drain(link, 1, timeout=.3), [],
                         'read a packet from a different conversation')


class RelaySessionTests(unittest.TestCase):
    """The real relay and proxy loops, over a fake conversation and a fake sshd."""

    def setUp(self):
        self.key = secrets.token_bytes(32)
        self.wire = Wire()

    def serve_in_background(self, cfg, once=True):
        end = self.wire.end()
        thread = threading.Thread(target=p.serve, args=(end, self.key, cfg, once),
                                  daemon=True)
        thread.start()
        self.addCleanup(thread.join, 1)
        return thread

    def collect(self, end, kinds, sid=None, timeout=8, role='S'):
        """Wait for the next packet of one of `kinds` (optionally for one sid)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            text = end.receive(.05)
            frame = p.decode(self.key, text) if text else None
            if (frame and frame['role'] == role and frame['kind'] in kinds
                    and (sid is None or frame['sid'] == sid)):
                return frame
        return None

    def test_full_session_moves_bytes_both_ways_and_ends_cleanly(self):
        target = FakeTarget(greeting=b'SSH-2.0-fake\r\n', echo=True)
        self.addCleanup(target.close)
        cfg = fast_config(target_host='127.0.0.1', target_port=target.port)
        self.serve_in_background(cfg)
        client = self.wire.end()
        to_proxy, write_fd = os.pipe()        # what "ssh" sends
        read_fd, from_proxy = os.pipe()       # what "ssh" receives
        self.addCleanup(lambda: [os.close(fd) for fd in (read_fd,) if fd])
        result = {}

        def run_client():
            try:
                sid = p.open_session(client, self.key, cfg)
                result['sid'] = sid
                p.session(client, self.key, sid, 'C', to_proxy, from_proxy,
                          lambda: os.close(from_proxy), cfg)
                result['ok'] = True
            except Exception as exc:                      # noqa: BLE001 - reported below
                result['error'] = exc

        thread = threading.Thread(target=run_client, daemon=True)
        thread.start()
        self.assertEqual(os.read(read_fd, 64), b'SSH-2.0-fake\r\n',
                         'greeting from the target did not arrive')
        os.write(write_fd, b'hello over imessage\n')
        self.assertEqual(os.read(read_fd, 64), b'HELLO OVER IMESSAGE\n',
                         'echoed bytes did not come back')
        os.close(write_fd)                                # "ssh" exits
        thread.join(10)
        self.assertFalse(thread.is_alive(), 'client session did not finish')
        self.assertIsNone(result.get('error'))
        self.assertTrue(result.get('ok'))
        self.assertEqual(bytes(target.received), b'hello over imessage\n')

    def test_relay_notices_its_socket_closed_even_with_a_full_window(self):
        # The target floods more than one window, then closes. The client never
        # acknowledges anything, so the window stays full for the whole test.
        target = FakeTarget(greeting=b'x' * 20000, close_after_greeting=True)
        self.addCleanup(target.close)
        cfg = fast_config(target_host='127.0.0.1', target_port=target.port)
        thread = self.serve_in_background(cfg)
        client = self.wire.end()
        first = secrets.token_hex(16)
        client.send(p.encode(self.key, first, 'C', 'O'))
        self.assertIsNotNone(self.collect(client, ('O',), first), 'relay did not open')
        data = self.collect(client, ('D',), first)
        self.assertIsNotNone(data, 'relay sent no data')
        time.sleep(.5)                                    # let the window fill and EOF land
        second = secrets.token_hex(16)
        client.send(p.encode(self.key, second, 'C', 'O'))
        opened = self.collect(client, ('O', 'R'), second)
        self.assertIsNotNone(opened, 'relay ignored the new client')
        self.assertEqual(opened['kind'], 'O',
                         'relay stayed busy after its own socket closed')
        thread.join(12)
        self.assertFalse(thread.is_alive(), 'relay did not return to idle')

    def test_new_client_preempts_a_silent_session(self):
        target = FakeTarget()                             # accepts, then stays quiet
        self.addCleanup(target.close)
        cfg = fast_config(target_host='127.0.0.1', target_port=target.port)
        self.serve_in_background(cfg)
        client = self.wire.end()
        first = secrets.token_hex(16)
        client.send(p.encode(self.key, first, 'C', 'O'))
        self.assertIsNotNone(self.collect(client, ('O',), first))
        client.send(p.encode(self.key, first, 'C', 'D', 0, -1, b'typed a bit\n'))
        self.assertIsNotNone(self.collect(client, ('A', 'D'), first), 'no ack of our data')

        second = secrets.token_hex(16)                     # client one now vanishes
        client.send(p.encode(self.key, second, 'C', 'O'))
        busy = self.collect(client, ('R', 'O'), second, timeout=4)
        self.assertIsNotNone(busy, 'relay said nothing to the second client')
        self.assertEqual(busy['kind'], 'R', 'relay dropped a live session immediately')
        self.assertIsNotNone(self.collect(client, ('P',), first, timeout=4),
                             'relay did not probe the session it was asked to drop')
        time.sleep(cfg['probe_grace'] + .2)
        client.send(p.encode(self.key, second, 'C', 'O'))
        opened = self.collect(client, ('O',), second, timeout=6)
        self.assertIsNotNone(opened, 'relay never yielded to the waiting client')

    def test_answering_a_probe_keeps_a_session(self):
        target = FakeTarget()
        self.addCleanup(target.close)
        cfg = fast_config(target_host='127.0.0.1', target_port=target.port)
        self.serve_in_background(cfg)
        client = self.wire.end()
        first = secrets.token_hex(16)
        client.send(p.encode(self.key, first, 'C', 'O'))
        self.assertIsNotNone(self.collect(client, ('O',), first))
        second = secrets.token_hex(16)
        for _ in range(3):
            client.send(p.encode(self.key, second, 'C', 'O'))
            probe = self.collect(client, ('P',), first, timeout=4)
            if probe:                                     # stay alive, as a real client does
                client.send(p.encode(self.key, first, 'C', 'A', ack=-1))
            reply = self.collect(client, ('O',), second, timeout=1)
            self.assertIsNone(reply, 'relay preempted a session that answered its probe')

    def test_relay_refuses_when_its_target_is_unreachable(self):
        closed = socket.socket()
        closed.bind(('127.0.0.1', 0))
        port = closed.getsockname()[1]
        closed.close()
        cfg = fast_config(target_host='127.0.0.1', target_port=port)
        self.serve_in_background(cfg, once=False)
        client = self.wire.end()
        sid = secrets.token_hex(16)
        client.send(p.encode(self.key, sid, 'C', 'O'))
        frame = self.collect(client, ('N', 'O', 'R'), sid)
        self.assertIsNotNone(frame, 'relay said nothing about an unreachable target')
        self.assertEqual(frame['kind'], 'N', 'unreachable sshd was not reported as fatal')

    def test_client_reports_a_fatal_refusal(self):
        cfg = fast_config()
        client = self.wire.end()
        relay = self.wire.end()

        def refuse():
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                text = relay.receive(.05)
                frame = p.decode(self.key, text) if text else None
                if frame and frame['role'] == 'C' and frame['kind'] == 'O':
                    relay.send(p.encode(self.key, frame['sid'], 'S', 'N'))
                    return

        threading.Thread(target=refuse, daemon=True).start()
        with self.assertRaises(RuntimeError):
            p.open_session(client, self.key, cfg)

    def test_client_waits_out_a_busy_relay(self):
        cfg = fast_config(connect_timeout=6)
        client = self.wire.end()
        relay = self.wire.end()
        state = {'busy': 0}

        def busy_then_accept():
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                text = relay.receive(.05)
                frame = p.decode(self.key, text) if text else None
                if frame and frame['role'] == 'C' and frame['kind'] == 'O':
                    state['busy'] += 1
                    kind = 'R' if state['busy'] < 2 else 'O'
                    relay.send(p.encode(self.key, frame['sid'], 'S', kind))

        threading.Thread(target=busy_then_accept, daemon=True).start()
        sid = p.open_session(client, self.key, cfg)
        self.assertTrue(sid)
        self.assertGreaterEqual(state['busy'], 2, 'client gave up on the first refusal')


@unittest.skipUnless(os.environ.get('IMSG_SSH_INTEGRATION') == '1',
                     'opt in: uses this machine\'s own localhost SSH login')
class SSHIntegrationTests(unittest.TestCase):
    def test_real_ssh_binary_and_local_sshd(self):
        with tempfile.TemporaryDirectory(prefix='imsg-ssh-', dir='/tmp') as tmp:
            root = Path(tmp)
            cfg = root / 'config.json'
            cfg.write_text(json.dumps(dict(key=secrets.token_hex(32), chat_id=1,
                                           target_host='127.0.0.1', target_port=22,
                                           retry_seconds=.5, ack_delay=0,
                                           connect_timeout=15)))
            wire = str(root / 'wire.sock')
            base = [sys.executable, str(Path(p.__file__).resolve())]
            server = subprocess.Popen(base + ['serve', '--config', str(cfg),
                                              '--test-socket', wire, '--once'],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True)
            try:
                deadline = time.monotonic() + 10
                while not Path(wire).exists() and time.monotonic() < deadline:
                    time.sleep(.05)
                proxy = shlex.join(base + ['proxy', '--config', str(cfg),
                                           '--test-socket', wire])
                result = subprocess.run(
                    ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                     '-o', 'HostKeyAlias=localhost', '-o', 'ConnectTimeout=20',
                     '-o', 'ProxyCommand=' + proxy, 'localhost',
                     "printf 'imsg-ssh-smoke-ok\\n'; printf 'stderr-ok\\n' >&2"],
                    capture_output=True, text=True, timeout=90)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, 'imsg-ssh-smoke-ok\n')
                self.assertIn('stderr-ok', result.stderr)
            finally:
                if server.poll() is None:
                    server.terminate()
                server.communicate(timeout=10)


if __name__ == '__main__':
    unittest.main()
