# Netwatch

**See what is on your network, and understand it.**

A headless network monitor with a browser dashboard, for servers that have no screen. It watches the
traffic your box already handles, learns which devices are on the network, lets you name them, and
tells you — in plain language — when something changed.

A fork of [Sniffnet](https://github.com/GyulyVGC/sniffnet) that adds `netwatchd`. Everything is
embedded in the binary: no GUI toolkit, no CDN, no API keys, **no LLM**. If a number is on the page,
a packet produced it.

```
                     your network, as netwatch sees it

  Devices      10 on the network · 6 online · 2 waiting to be named
  Traffic      1.28 M packets · 892.4 MB · 3,417 conversations
  Alerts       3 worth a look · 0 need action
```

## Quick start

```sh
git clone git@github.com:0xZenithdev/NetWatch-x.git
cd NetWatch-x
cargo build -p netwatchd --release
```

Capturing needs `CAP_NET_RAW` — a read-only monitoring capability. Netwatch never composes or injects
packets, and it never stores payloads (the capture snapshot is 128 bytes: headers, not content).

```sh
sudo setcap cap_net_raw,cap_net_admin=eip target/release/netwatchd
target/release/netwatchd --iface eth0
```

Then open <http://127.0.0.1:8790>. To reach it from a phone or another machine without exposing it to
the internet:

```sh
tailscale serve --bg 8790
```

Use `tailscale serve` (tailnet only) rather than `tailscale funnel` (public internet) unless you have
added authentication — a live view of your server's connections is not something to publish openly.

## The dashboard

Five tabs, and a **Glossary** tab that explains every term the rest of the page uses. Any term with a
dotted underline is a button: tap it and the explanation opens in place, so you never have to leave
the page you were reading.

**Overview** — the state of things in one screen: a plain-English headline, packet and volume totals,
a throughput graph for the last few minutes, what the traffic is being used for (with service names
like `https`, `dhcp`, `tailscale`), and the busiest devices. It also states what Netwatch cannot see,
so you know the size of the blind spot rather than assuming there isn't one.

**Devices** — one row per device: the name you gave it, its maker, its address, when it was last
heard from, and how much it has moved. Filter by online / offline / waiting to be named / randomised
address. Search by name, address, maker or kind. Tap a device to open its full record — rename it,
set its kind, set trust, write a note — plus its addresses over time, who it talks to, which ports it
uses, the names it asked for, its online/offline timeline, and its alert history.

**Traffic** — every conversation, newest or largest first, with the service label for the port, the
peer's name, how many bytes each way, and how long ago it started. This is where you answer "what is
my server actually doing right now".

**Alerts** — everything the daemon noticed, with a severity, the device it concerns, and a **"Why did
this fire?"** section explaining the rule and the numbers behind it. Filterable by severity and kind.

**Glossary** — 50 terms, searchable. `Promiscuous mode`, `OUI`, `SNI`, `flap suppression`, `mDNS`,
`what does "offline" mean here` — the answer is in the page, not in a search engine.

## Devices and naming

Everything is learned **passively**, from the traffic this box already handles. Nothing is scanned,
nothing on the network is disturbed, and no scan noise is generated.

- **Which device** — the source MAC of each frame, plus the destination MAC when it belongs to a host,
  so a download-heavy device is noticed too. Broadcast, multicast and the daemon's own addresses are
  excluded, and each device keeps at most eight addresses.
- **The maker** — read from the IEEE's own OUI registry (about 38,000 prefixes), embedded in the
  binary and regenerable with `tools/build-oui`. Never guessed.
- **A randomised address** — recognised from the locally-administered bit in the MAC. A phone
  rotating its private Wi-Fi address is labelled as such, the maker is *not* claimed for it, and the
  device is not called an intruder for something it is designed to do.
- **A name** — suggested from mDNS (`.local`) names and IPv4 reverse lookups the device itself asks
  for, and never overriding a name you typed.
- **Same address, two devices** — noticed, and reported as `mac_conflict` rather than silently
  crediting one device with another's traffic.
- **One device, two addresses** — a device that changed address and was never online under both at
  once is flagged as *possibly the same device*, as a suggestion to merge, never an automatic merge.

**What it cannot do, stated plainly:** it cannot read a name out of encrypted DNS, so a device using
DoH or DoT looks anonymous. It cannot see inside TLS, so it reports the port and the peer, not the
page. It cannot attribute traffic to a process without running as root and reading `/proc`, which this
does not do. Anything it does not know is `null` in the API and "unknown" on the page — never a
plausible-looking guess.

## Alerts

The daemon appends alerts to a JSON-lines spool and serves the most recent from `/api/alerts`. A
separate `tools/netwatch-notify` delivers them to Telegram.

Delivery is deliberately **not** part of the daemon: `netwatchd` keeps no HTTP or TLS dependency,
delivery can be fixed or reconfigured without restarting capture, and an unreachable Telegram can
never stall packet capture. The reader advances its offset only after Telegram accepts a message, so a
failure retries instead of losing the alert.

| Kind | Means |
|---|---|
| `new_device` | a MAC this box has never seen before joined the network |
| `device_offline` | a device has been silent for **15 minutes** (not for the 5 minutes the dashboard uses to draw it as offline) |
| `device_back_online` | it came back |
| `address_change` | a known device started using a new address as well |
| `mac_conflict` | two MACs claimed one address within 10 minutes |
| `new_peer` | a device talked to a peer it has never talked to before |
| `traffic_spike` | a device moved 8× its own usual volume in one minute *and* more than 2 MB |
| `capture_failed` | the monitor stopped seeing traffic — the failure that matters most |
| `quota_exceeded` | a device passed the daily budget you set for it (once a day, not once per gigabyte) |
| `test` | written by `--test-alert`, to prove the path end to end |

**Flap suppression.** A phone sleeping its Wi-Fi used to produce an alert every ten minutes; that is
how an alert channel gets muted and stops being a control. So: a new device still alerts instantly,
going offline needs 15 minutes of silence, and a device that comes back is noticed but cannot alert
again for 6 hours. Repeats are collapsed rather than queued.

**Per-device rules.** Each device carries its own answer to "how loudly should this interrupt me":
`default` (everything), `quiet` (only things that need action, such as two devices fighting over one
address) or `never`. The rule is applied where the alert is *raised*, and the alert records the
decision it was given — so the dashboard and the spool keep every fact, the notifier skips the ones
marked `muted`, and exactly one place decides. `quiet` is not the same as `ignored`: an ignored device
is left out of the counts entirely.

```sh
# 1. create a bot with @BotFather, then message it and read the chat id:
curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" | grep -o '"chat":{"id":[-0-9]*'

# 2. configure
cp examples/notify.json /etc/netwatch/notify.json   # fill in token + chat id

# 3. see exactly what would be delivered, then prove the path end to end
tools/netwatch-notify --config /etc/netwatch/notify.json --explain
netwatchd --test-alert --alerts /var/lib/netwatch/alerts.jsonl
tools/netwatch-notify --config /etc/netwatch/notify.json --dry-run
```

The first run does **not** replay history. A monitor that has been spooling for a week would otherwise
deliver hundreds of stale alerts the moment it is switched on, which trains the reader to ignore the
channel. Pass `--replay` to send the backlog deliberately; `--max-age-hours` (default 24) bounds even
that. `muted_kinds` silences one rule without touching the daemon. `packaging/netwatch-notify.timer`
polls every 30 seconds; `--follow` stays running instead.

## History, uptime and budgets

The live view is memory, and memory dies with the process. `--history` adds a SQLite file (WAL mode,
`synchronous=NORMAL`) that keeps **one row per device per day** plus closed sessions:

* bytes each way, packets, seconds online and session count, per UTC day;
* a device page reads its own last 30 days, and the overview draws the network's last 30;
* uptime is seconds-online over the days a device was actually seen, so a device that only appears in
  the evening is not punished for the morning;
* rows older than `--history-days` (default 365) are deleted automatically.

**What it costs.** The keeper thread flushes once every 30 seconds, in a single transaction, touching
only devices whose counters moved — the work is proportional to the number of devices, never to the
number of packets. Nothing is written per packet, so a busy LAN costs the same as an idle one. Measured
on this host, 365 days of retention for a handful of devices is a few megabytes, at **11.5 MB RSS and
well under 1% of one core** — against 97 MB and a 1.2 GB peak for the previous single-file daemon.

**Budgets.** Set a daily gigabyte budget per device on its page and Netwatch adds that device's traffic
from midnight UTC. Crossing it raises exactly one alert for the day. The figure comes from the same
counter the device page shows, so the alert and the page cannot disagree. Budgets are stored with the
inventory (`--devices`), not with the measurements, because they are intent rather than observation.

## Options

```
-i, --iface <NAME>      interface to capture on (default: first non-loopback)
    --bind <ADDR>       address to serve on (default: 127.0.0.1)
-p, --port <PORT>       port to serve on (default: 8790)
    --alerts <PATH>     append alerts here as JSON lines
    --devices <PATH>    keep the device inventory here (default: beside --alerts)
    --history <PATH>    keep the long-term record here as SQLite (default: beside --devices)
    --history-days <N>  how many days to keep (default: 365)
    --no-dns-names      do not read names out of plaintext DNS
    --demo              serve the dashboard with synthetic traffic, capture nothing
    --list              list capture interfaces
    --test-alert        write one test alert and exit
-h, --help
```

`--devices` is the difference between a tool and a toy: without it, every restart re-learns the whole
network and re-announces it as new. With `--alerts` set it defaults to `devices.json` in the same
directory, which is what the shipped unit uses. `--history` defaults to `history.db` beside it; pass
`--history ""` to switch retention off on a box with no room for it.

## Endpoints

| Path | Purpose |
|---|---|
| `/` | the dashboard (embedded, no external assets, auto-refreshes) |
| `/api/summary` | counts, throughput series, protocol split, busiest devices, top ports |
| `/api/devices` | the inventory, with counts and the review queue |
| `/api/devices/<mac>` | one device in full: addresses, peers, ports, names, timeline, alerts |
| `/api/flows` | conversations; `?q=` searches by name, service, address, port; `?proto=`, `?local=` |
| `/api/alerts` | recent alerts; `?severity=`, `?kind=`, `?mac=` |
| `/api/history?days=30` | what was kept: per-day network totals, and uptime per device |
| `/api/glossary` | every term the dashboard uses, with explanations |
| `/api/export?what=devices\|flows\|alerts&format=csv\|json` | a download |
| `/healthz` | liveness probe |
| `/api/devices/<mac>` (PUT) | rename, re-type, re-trust, annotate, set the budget, set the notification rule |

## Design notes

- **The failure path is part of the UI.** Without `CAP_NET_RAW` the daemon still starts and the
  dashboard says exactly what is wrong, including the `setcap` command for the binary's real path. It
  does not quietly display zero traffic.
- **Every claim is checkable.** The dashboard's "how does it know this?" panel names the interface it
  is reading, the snapshot length, the size of the vendor table, and the two addresses it considers
  its own.
- **Binds to loopback by default**, so publishing is a deliberate act rather than an accident.
- **No external assets.** The dashboard is embedded in the binary: no CDN, no fonts to fetch, nothing
  that phones home.
- **Headers only.** Snaplen 128: enough to read addresses, ports and DNS question names, not enough to
  retain content.
- **A conversation is one row.** Both directions fold into one entry with the endpoints in canonical
  order, so a request and its reply cannot appear as two half-conversations. "Sent" and "received" are
  stated relative to a device this network knows; traffic between two strangers claims no direction at
  all rather than guessing.
- **Wall-clock timestamps.** "First seen" is a real time, so it survives a restart and means the same
  thing in the spool, the API and the alert.
- **Bounded state.** Flows, devices, addresses, names and buckets all have ceilings, so a busy network
  cannot grow the process until it dies.
- **Read-only.** `CAP_NET_RAW` is needed to observe; nothing is ever transmitted or modified.

## Status

`netwatchd` reports devices, flows, protocols, volumes, alert history and a documented glossary, with
an inventory that survives restarts. Not done: per-process attribution, authentication (the daemon is
loopback-only and expects `tailscale serve` in front), IP geolocation, and historical retention beyond
the in-memory window.

The original Sniffnet desktop application is retained in this repository and builds from the root
crate. See [`docs/BUILDING.md`](docs/BUILDING.md): the daemon needs libpcap and nothing else, while the
desktop app additionally needs `pkg-config` and `libasound2-dev` for its audio dependency.

## Licence

Dual-licensed **MIT OR Apache-2.0**, same as upstream. This is a fork of Sniffnet — see
[`NOTICE.md`](NOTICE.md) for upstream attribution and the list of modifications.
