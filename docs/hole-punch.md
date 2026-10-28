# Reaching a qshd behind NAT: UDP hole punching (experimental)

A host behind NAT cannot be dialled: packets that do not match a mapping its
NAT already has are dropped. `qsh punch` makes both sides create that mapping
at the same time, so that a normal qsh connection can run through the hole.

The third party this needs is only a signalling channel (a chat message) and a
public STUN server: neither carries the session. Compare with `qsh -R`
(see "Hosts without an open port" in the README), which needs a public host
with qshd and carries all the traffic through it.

## How it works

1. Each side sends a STUN binding request and learns the public address its
   NAT gives to the punching socket.
2. The two sides exchange those addresses out of band.
3. Both then send a UDP packet to the other's public address once a second.
   Each packet creates the NAT mapping on the sending side, so the first
   packets that cross open the path in both directions.
4. The packets carry a normal qsh connection: `serve` passes them to the local
   qshd, `dial` listens on loopback for the local `qsh`. TLS and the host key
   check are still between `qsh` and `qshd`; the punching secret only keeps
   stray packets out.
5. The one-second packets also keep the mapping alive. When a NAT starts using
   a different port for us, the tunnel notices and follows it.

## What it cannot do

- **Symmetric NAT and most CGNAT.** Their mapping depends on the destination,
  so the address STUN reports is not the one the peer needs. `dial` prints a
  warning when two STUN servers see different ports; `qsh -R` through a
  reachable host is then the answer.
- **Replace a relay for reliability.** There is no fallback: if the hole does
  not open, nothing happens. This is why the feature is experimental.
- **Work without exchanging addresses.** Something must carry one line of text
  between the two people.

## Using it

On the host behind NAT (the one running `qshd`, Windows included):

```sh
qsh punch serve --id "some shared phrase"
# qsh punch: punched socket on 0.0.0.0:53412
# qsh punch: STUN says your address is 203.0.113.5:53412
```

Send that address and the shared phrase to the other side, then paste theirs
when `serve` asks for it (or pass `--peer`). On the other side:

```sh
qsh punch dial --peer 203.0.113.5:53412 --id "some shared phrase"
# qsh punch: STUN says your address is 198.51.100.9:61002
# qsh punch: punching 203.0.113.5:53412, listening for qsh on 127.0.0.1:4422
# qsh punch: in another terminal, connect with `qsh 127.0.0.1`
```

Send your own address back to the first side and paste it there. Then, in
another terminal:

```sh
qsh 127.0.0.1                  # or: qsh cp file.txt 127.0.0.1:
```

`dial` listens on 4422 by default so that the punched host keeps the same host
key entry as a normal connection. If that port is taken (a local `qshd`), use
`--listen 127.0.0.1:4501` and then `qsh -p 4501 --accept-new-host 127.0.0.1`
the first time.

Options worth knowing:

- `--punch-port N` keeps the local UDP port between runs, so a NAT mapping
  that is still alive is reused.
- `--no-stun` skips STUN (loopback tests, or a public address found another way).
- `--to 127.0.0.1:4422` (on `serve`) says where the local qshd listens.
- `--id` is required to match on both sides; a random one is printed when it
  is missing.

Keep both `qsh punch` processes running for as long as the tunnel is needed
(`tmux`, `nohup`, or a service of your own). Stopping either closes the hole.

## What crosses the hole

Only the qsh protocol, end to end encrypted and authenticated by `qshd`. An
attacker who learns the shared phrase still faces the normal login: the
punched socket leads to the same qshd, with the same keys, passwords and
one-time codes. Nothing is relayed through a third machine.
