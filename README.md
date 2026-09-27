# Netwatch

Network flow monitoring with a **browser dashboard**, for servers that have no screen.

A fork of [Sniffnet](https://github.com/GyulyVGC/sniffnet) that adds `netwatchd`: a headless daemon
that captures packets, aggregates them into flows, and serves a small self-contained dashboard you can
reach from any device. Built for headless boxes reached over Tailscale or a private network — no GUI
toolkit, no ALSA, no fontconfig, no API keys, no CDN.

```
┌─ netwatch ────────────────── iface enp2s0 · live · 3h 12m ─┐
│  packets        volume        flows        dropped          │
│  1,284,301      892.4 MB      3,417        0                │
│                                                             │
│  protocols      TCP 74%   UDP 25%   other 1%                │
│  destinations   142.250.185.46 · 1.2 MB                     │
│  conversations  TCP ↔ 142.250.185.46:443 84.2 KB ↑12.1 ↓72.1 │
└─────────────────────────────────────────────────────────────┘
```

## Quick start

```sh
git clone git@github.com:0xZenithdev/NetWatch-x.git
cd NetWatch-x
cargo build -p netwatchd --release
```

Capturing needs `CAP_NET_RAW` — a read-only monitoring capability. Netwatch never composes or injects
packets, and it never stores payloads (the capture snaplen is set to headers only).

```sh
sudo setcap cap_net_raw,cap_net_admin=eip target/release/netwatchd
target/release/netwatchd --iface eth0
```

Then open <http://127.0.0.1:8790>. To see it from another device without exposing it publicly:

```sh
tailscale serve --bg 8790
```

Use `tailscale serve` (tailnet only) rather than `tailscale funnel` (public internet) unless you have
added authentication — a live view of your server's connections is not something to publish openly.

### Options

```
-i, --iface <NAME>   interface to capture on (default: first non-loopback)
    --bind <ADDR>    address to serve on (default: 127.0.0.1)
-p, --port <PORT>    port to serve on (default: 8790)
    --demo           serve the dashboard without capturing
    --list           list capture interfaces
-h, --help
```

### Endpoints

| Path | Purpose |
|---|---|
| `/` | the dashboard (embedded in the binary, auto-refreshes every 2 s) |
| `/api/stats` | JSON: totals, per-protocol volume, top destinations, top flows |
| `/healthz` | liveness probe |

## Design notes

- **The failure path is part of the UI.** Without `CAP_NET_RAW` the daemon still starts and the
  dashboard tells you exactly what is wrong, including the `setcap` command for the binary's real
  path. It does not quietly display zero traffic.
- **Binds to loopback by default**, so publishing is a deliberate act rather than an accident.
- **No external assets.** The page is a single embedded string: no CDN, no fonts to fetch, nothing
  that phones home.
- **Headers only.** Snaplen 128: enough to read addresses and ports, not enough to retain content.
- **A conversation is one row.** Both directions fold into a single entry with the endpoints in
  canonical order, so a request and its reply cannot appear as two half-conversations. "Up" and
  "down" are named relative to the interface's own addresses; for traffic that is merely routed
  through, no direction is claimed rather than guessing.
- **Read-only.** `CAP_NET_RAW` is needed to observe; nothing is ever transmitted or modified.

## Alerts

The daemon appends alerts to a JSON-lines spool and serves the most recent ones
from `/api/stats`. A separate `tools/netwatch-notify` delivers them to Telegram.

Delivery is deliberately **not** part of the daemon: netwatchd keeps no HTTP or
TLS dependency, delivery can be fixed or reconfigured without restarting
capture, and an unreachable Telegram can never stall packet capture. The reader
only advances its offset after Telegram accepts a message, so a failure retries
instead of losing the alert.

```sh
# 1. create a bot with @BotFather, then message it and read the chat id:
curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" | grep -o '"chat":{"id":[-0-9]*'

# 2. configure and test
cp examples/notify.json ~/.config/netwatch/notify.json   # fill in token + chat id
tools/netwatch-notify --config ~/.config/netwatch/notify.json --dry-run
tools/netwatch-notify --config ~/.config/netwatch/notify.json --test

# 3. prove the whole path without waiting for a real event
netwatchd --test-alert --alerts /path/to/alerts.jsonl
tools/netwatch-notify --config ~/.config/netwatch/notify.json
```

`min_severity` (`info`, `notable`, `alert`) filters at delivery time, so raising
it suppresses noise without touching the daemon. `--follow` keeps the notifier
running instead of draining once; `packaging/netwatch-notify.timer` polls every
30 seconds instead.

## Status

`netwatchd` currently reports bandwidth, volume, protocols, top destinations and top flows. Planned,
in rough order: per-process attribution, a searchable flow history, authentication, and IP geolocation.

The original Sniffnet desktop application is retained in this repository and builds from the root
crate. See [`docs/BUILDING.md`](docs/BUILDING.md): the daemon needs libpcap and nothing else, while
the desktop app additionally needs `pkg-config` and `libasound2-dev` for its audio dependency.

## Licence

Dual-licensed **MIT OR Apache-2.0**, same as upstream. This is a fork of Sniffnet — see
[`NOTICE.md`](NOTICE.md) for upstream attribution and the list of modifications.
