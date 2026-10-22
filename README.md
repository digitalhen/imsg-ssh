# imsg-ssh — SSH over iMessage

Carry an SSH session home inside ordinary text messages.

If your Mac at home has no reachable address — behind CGNAT, on a captive
network, on a boat with a satellite messaging plan, on hotel Wi-Fi that blocks
everything except Apple's push service — but iMessage still gets through, then
you still have a byte pipe. `imsg-ssh` turns that pipe into an OpenSSH
`ProxyCommand`, so `ssh` works normally over it:

```sh
$ imsg_ssh.py connect 'uptime; df -h /'
imsg-ssh: opening SSH over iMessage; the handshake takes a few minutes
 19:44  up 6 days, 11:04, 3 users, load averages: 1.42 1.63 1.71
Filesystem      Size    Used   Avail Capacity  Mounted on
/dev/disk3s1s1  1.8Ti   9.9Gi   412Gi     3%   /
```

It is slow — think a few hundred bytes per second and seconds of typing latency
— and it is wonderful for exactly the cases where nothing else works.

SSH itself still does all the cryptography: host-key verification, user
authentication, encryption. This project only moves bytes, and the relay only
ever connects to the one sshd named in its own config file.

## Requirements

- Two Macs, both signed into Messages, sharing one conversation. Messaging
  yourself (your own Apple account) works well and keeps the traffic private.
- Python 3.9 or newer. Standard library only; no packages to install.
- **Full Disk Access** for the terminal (or app) that runs `imsg_ssh.py` on each
  Mac — it reads the local Messages database. System Settings → Privacy &
  Security → Full Disk Access, then restart the terminal.
- Permission to control Messages when sending (macOS prompts once).
- **Remote Login** enabled on the home Mac (System Settings → General → Sharing),
  plus whatever SSH key or password you normally use. Set that up and test it on
  the local network first: if `ssh` does not work at home, it will not work here
  either.
- Optional: [`imsg`](https://github.com/steipete/imsg) (`brew install
  steipete/tap/imsg`). If present it is used for sending; otherwise AppleScript
  is.

## Install

On **both** Macs:

```sh
git clone https://github.com/<you>/imsg-ssh.git ~/imsg-ssh
cd ~/imsg-ssh
python3 -m unittest -q test_imsg_ssh      # optional, ~20s, sends nothing
```

### Home Mac (the one you want to reach)

```sh
python3 imsg_ssh.py init                  # fresh config + 256-bit shared key
python3 imsg_ssh.py setup                 # pick the shared conversation
python3 imsg_ssh.py install-agent         # run the relay at login, forever
python3 imsg_ssh.py export                # one line to carry to the laptop
```

`setup` lists this Mac's conversations and asks which one to use. `export`
prints a bundle containing the shared key, your username and this Mac's SSH host
key. **Treat that line like a password.**

### Laptop (the one you will be sitting at)

```sh
python3 imsg_ssh.py import <the-line-from-export>
python3 imsg_ssh.py setup                 # pick the same conversation, locally
python3 imsg_ssh.py connect hostname      # the real end-to-end test
```

Chat row ids are per-Mac: the number from the home Mac means something different
on the laptop, which is why each end runs `setup` for itself. Once the two ends
have exchanged any packet, `setup` finds the right conversation by itself.

`import` also pins the home Mac's SSH host key in `~/.config/imsg-ssh/known_hosts`,
so the first connection verifies instead of asking. Do not disable host-key
checking to work around an error — it means the key changed.

## Use

```sh
# One-shot command: by far the best fit for a messaging link.
python3 imsg_ssh.py connect 'tail -50 /var/log/system.log'

# Interactive shell. Expect to feel every keystroke.
python3 imsg_ssh.py connect

# Survive link interruptions: keep the remote work inside tmux.
python3 imsg_ssh.py connect --tty 'tmux new-session -A -s imessage'
```

Everything after `connect` is passed to the remote shell. `connect` enables SSH
compression and pins the host key; it is a thin wrapper around:

```sh
ssh -C -o ProxyCommand='python3 imsg_ssh.py proxy' ... user@imsg-ssh-home
```

so any ssh option you need can be added the same way. Because it is a real
ProxyCommand, `scp`, `rsync -e`, `ssh -L` and friends work too — but remember
what the pipe costs before copying anything large.

### What to expect

Payload is 1200 bytes per message, paced 1.5s apart per direction, four packets
in flight: a ceiling near 800 bytes per second each way. Measured between two
Macs on ordinary broadband, messaging the same Apple account:

| what | time | messages |
| ---- | ---- | -------- |
| `connect hostname` — full handshake, command, clean exit | 23s | 10 each way |
| interactive shell to first prompt | 25s | — |
| one command typed into that shell | ~3s | 2 each way |
| reconnect after the previous client was killed with `-9` | 64s | — |

An SSH handshake is about 3KB each way, and that is what the first twenty
seconds are spent on. After that a round trip is a few seconds. Notes:

- `tmux` or a one-shot command is much more pleasant than a raw shell, and
  survives the link dropping.
- Chatty output, full-screen programs (`top`, `vim`) and large transfers are a
  poor fit. SSH compression helps text a lot and encrypted payloads not at all.
- Apple's rate limits are undocumented and may add delay. Raise
  `message_interval` if you see sends being throttled.
- Latency on the messaging path itself dominates everything. A satellite or
  ship plan will be slower than the numbers above, and the defaults are chosen
  to tolerate that rather than to look fast here.

## Reliability

The link is assumed hostile: messages arrive late, twice, out of order or never.
Each direction is a sliding window with cumulative ACKs, retransmission with
backoff and an ordered EOF, so the byte stream SSH sees is exact. See
[PROTOCOL.md](PROTOCOL.md) for the wire format and the session rules.

Notable behaviours worth knowing about:

- **One session at a time.** A second client is told the relay is busy and keeps
  asking. If the first client has died, the relay hands the session over within
  about half a minute; if it is merely idle, it answers a probe and keeps it.
- **Clean exits are immediate.** The proxy sends a close packet when `ssh` exits,
  including when it is killed, so the relay is free at once.
- **Idle is not dead.** Each end probes a silent peer and waits for
  `peer_timeout` (300s) of real silence before giving up, so a slow link is not
  mistaken for a broken one.
- **The relay survives restarts**, but an SSH connection cannot be resumed
  across one. That is what `tmux` is for.

## Configuration

`~/.config/imsg-ssh/config.json`, mode 600:

| key                 | default         | meaning                                        |
| ------------------- | --------------- | ---------------------------------------------- |
| `key`               | generated       | 32-byte shared transport key, hex              |
| `chat_id`           | from `setup`    | this Mac's chat row id                         |
| `handle`            | from `setup`    | conversation handle, used by the AppleScript sender |
| `target_host/_port` | `127.0.0.1:22`  | the only sshd the relay will connect to        |
| `ssh_user`          | your username   | user for `connect`                             |
| `message_interval`  | `1.5`           | minimum seconds between sends                  |
| `poll_seconds`      | `0.25`          | how often the Messages database is polled      |
| `ack_delay`         | `2.0`           | how long a bare ACK waits for data to carry it |
| `retry_seconds`     | `20`            | first retransmission delay                     |
| `keepalive_seconds` | `120`           | silence before probing the peer                |
| `peer_timeout`      | `300`           | silence before abandoning a session            |
| `session_timeout`   | `14400`         | maximum session length                         |
| `sender`            | `auto`          | `auto`, `imsg` or `applescript`                |

## Operating the relay

```sh
python3 imsg_ssh.py doctor                               # access, sender, sshd
launchctl print gui/$(id -u)/com.imsg-ssh.relay          # is it running
launchctl kickstart -k gui/$(id -u)/com.imsg-ssh.relay   # restart, dropping any session
tail -f ~/Library/Logs/imsg-ssh.log                      # what it is doing
python3 imsg_ssh.py uninstall-agent                      # stop for good
```

The home Mac must stay awake, signed into Messages, with Remote Login on. A
LaunchAgent runs in your GUI session, which is what gives it access to Messages;
it does not run while you are logged out.

## Troubleshooting

| symptom | cause |
| ------- | ----- |
| `cannot open .../chat.db` | Full Disk Access not granted to *this* terminal, or not restarted since |
| `doctor` shows 0 packets and `connect` times out | the two ends are on different conversations; rerun `setup` on both |
| `relay did not answer` | home Mac asleep, logged out, or the relay is not running |
| `relay refused: it could not reach its configured sshd` | Remote Login is off on the home Mac |
| Host key verification failed | the pinned key no longer matches; re-run `export`/`import` deliberately |
| sends logged as unconfirmed | Messages automation permission, or Apple throttling; check the conversation by eye |

`doctor` proves it can read the database, find a sender and reach sshd. It
cannot prove Apple will deliver anything — only a real `connect` does that.

## Security

The shared key authenticates the transport with HMAC-SHA256 and keeps imsg-ssh
traffic separate from everything else in the conversation; it is not the thing
protecting your session. SSH is: the relay's bytes go to one fixed sshd, and
authentication and encryption happen end to end between your laptop's ssh and
that sshd.

Still, be clear-eyed about the medium. Packets pass through Apple's
infrastructure and are stored in the Messages database on both Macs and on any
other device signed into the same account. The exported bundle contains the
shared key. Anyone who can read the key and write into the conversation can
reach the login prompt of your sshd — no further than SSH itself allows, but
that is the exposure.

## Tests

```sh
python3 -m unittest -v test_imsg_ssh
```

Covers framing and authentication, loss, reordering, duplication and EOF in both
directions, bounded windows and retry budgets, delayed-ACK behaviour, reading
bodies from both `text` and `attributedBody`, and — against a stand-in for
Messages and a stand-in for sshd — the real relay and proxy loops: a full
session, close detection with a full send window, handover from a dead client,
and refusal of handover by a live one. Nothing is sent to Apple.

```sh
IMSG_SSH_INTEGRATION=1 python3 -m unittest -v test_imsg_ssh
```

Additionally drives real OpenSSH and the local sshd over a Unix-socket stand-in
for the conversation. Needs a working key-authenticated `ssh localhost`.

## License

MIT — see [LICENSE](LICENSE).
