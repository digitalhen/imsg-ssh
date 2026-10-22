# The imsg-ssh wire protocol

The link is a conversation in Messages. It delivers short text strings with high
latency, no ordering guarantee, occasional duplication, occasional loss, and a
rate limit nobody documents. On top of that imsg-ssh provides a single reliable,
ordered, authenticated byte stream in each direction — enough for SSH, which
supplies its own encryption and identity checks on top.

## Packet format

One packet is one message. Its text is ASCII:

```
CB1 SSH1 <base64url(json)> <hex(hmac_sha256(key, base64url(json)))>
```

The JSON is a fixed seven-element array:

| field     | type   | meaning                                                   |
| --------- | ------ | --------------------------------------------------------- |
| sid       | string | 32 lowercase hex digits; identifies one session           |
| role      | `C`/`S`| sender: client (laptop) or server (home relay)            |
| kind      | string | one of the kinds below                                     |
| seq       | int    | sequence number for `D`/`E`, otherwise `-1`               |
| ack       | int    | highest contiguous sequence received, or `-1`             |
| timestamp | int    | unix seconds, used only to expire stale `O` packets       |
| payload   | string | base64 of at most 1200 raw bytes; empty unless kind `D`   |

The HMAC covers the whole encoded body, so sid, role, kind, seq, ack, timestamp
and payload are all authenticated. A packet that fails the MAC, has an unknown
kind or role, a malformed sid, an oversized payload, or a payload on a kind that
may not carry one is discarded without comment. Encoded packets stay under 4096
characters.

`CB1 SSH1 ` is only a marker: it lets a human reading the conversation (and any
other bridge sharing it) recognise and skip these messages. It provides no
security — the MAC does.

## Kinds

| kind | direction | meaning                                                         |
| ---- | --------- | --------------------------------------------------------------- |
| `O`  | both      | open a session; the relay echoes `O` to accept                  |
| `D`  | both      | stream data at `seq`                                            |
| `E`  | both      | end of stream at `seq`: ordered EOF, no payload                 |
| `A`  | both      | acknowledgement only                                            |
| `P`  | both      | liveness probe; the peer answers with `A`                       |
| `R`  | relay     | busy or reset — the client may retry                            |
| `N`  | relay     | fatal refusal (the relay cannot reach its own sshd)             |
| `X`  | client    | close: the client is finished, release the session now          |

## Reliability

Each direction is an independent sliding window of four unacknowledged packets.
`ack` is cumulative: it names the highest contiguous sequence the sender has
received, so one `ack` retires every earlier packet. Out-of-order data is
buffered only inside the window, which bounds memory even against an
authenticated peer that misbehaves. An `E` packet is ordered with the data, so a
stream never ends before its bytes are delivered.

Unacknowledged packets are retransmitted after `retry_seconds` (default 20),
then with 1.6× backoff up to four times that interval, for at most twenty
attempts. Duplicates are discarded by sequence number, but they always provoke a
fresh `ack`, because a duplicate usually means an earlier `ack` was lost.

Both ends read their local socket into a buffer that is independent of the send
window. A full window must never hide the fact that the local side has closed —
that is what makes a finished session detectable rather than merely silent.

ACKs are held back for `ack_delay` (default 2s) so that outgoing data can carry
them, which roughly halves the number of messages on a mostly one-way stream. An
ACK is sent immediately anyway when the peer's window is about to stall or when
the peer has signalled EOF.

## Sessions

The relay serves one session at a time; `target_host`/`target_port` in its own
config are the only place it will ever connect.

1. The client picks a random sid and sends `O` every `retry_seconds` until the
   relay answers `O` (accepted), `R` (busy — keep trying) or `N` (fatal).
2. The relay connects to its configured sshd, answers `O`, and pumps bytes.
3. Either side's EOF travels as `E`; the client sends `X` when it exits so the
   relay is free immediately rather than after a timeout.

A session that goes quiet is not assumed dead. After `keepalive_seconds` of
silence each end sends `P`; the peer answers `A`. Only after `peer_timeout`
(default 300s) without any authenticated traffic is the session abandoned.

Handover is explicit rather than first-come-first-served. When a fresh `O` with
a new sid arrives during a session, the relay:

- hands over at once if its own socket has already closed (nothing is left to
  deliver), otherwise
- answers `R` to the newcomer and sends `P` to the current peer, and
- hands over only if that peer stays silent for `probe_grace` (default 20s)
  across a probe, so a live session survives and a dead one is reclaimed in
  well under a minute.

A client from an already-abandoned session gets `R` once, so it fails fast
instead of waiting out its own timeout. Sessions that have finished are
remembered for the life of the relay process and never reopened, so a replayed
`O` cannot resurrect one. An `O` whose timestamp is more than five minutes old
is ignored altogether.

## Reading and sending messages

Packets are read straight from `~/Library/Messages/chat.db` (read-only) by
polling for rows newer than the last row id seen at startup, so history is never
replayed. A body is taken from the `text` column when it is there and otherwise
extracted from the `attributedBody` blob: Messages stores many messages only in
the blob, and it may clear `text` on messages it already stored. A reader that
trusts `text` alone silently loses most packets. Identical packet text is
delivered once, because a conversation with yourself stores both a sent and a
received copy of every message.

Sending uses [`imsg`](https://github.com/steipete/imsg) when it is installed and
AppleScript against Messages otherwise. Sends are paced at least
`message_interval` seconds apart (default 1.5).

## What this protocol does not do

It does not encrypt (SSH does), compress (SSH does, and `connect` enables it),
authenticate the peer's identity beyond possession of the shared key (SSH host
keys and user authentication do), or resume a session across a relay restart.
The shared key authenticates the transport and separates it from unrelated
traffic in the same conversation; it is not a substitute for SSH's own
cryptography.
