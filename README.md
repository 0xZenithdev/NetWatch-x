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
│  flows          10.0.0.5:52344 → 1.1.1.1:443  TCP 84.2 KB   │
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
- **Read-only.** `CAP_NET_RAW` is needed to observe; nothing is ever transmitted or modified.

## Status

`netwatchd` currently reports bandwidth, volume, protocols, top destinations and top flows. Planned,
in rough order: per-process attribution, a searchable flow history, authentication, and IP geolocation.

The original Sniffnet desktop application is retained in this repository and builds from the root
crate. See [`docs/BUILDING.md`](docs/BUILDING.md) — the daemon needs only libpcap, while the desktop
app needs the full GTK/ALSA/fontconfig toolchain.

## Licence

Dual-licensed **MIT OR Apache-2.0**, same as upstream. This is a fork of Sniffnet — see
[`NOTICE.md`](NOTICE.md) for upstream attribution and the list of modifications.
