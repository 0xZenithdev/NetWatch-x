# Changelog

Netwatch starts its own history here. For upstream Sniffnet's changelog, see
<https://github.com/GyulyVGC/sniffnet/blob/main/CHANGELOG.md>.

## v0.1.0 — unreleased

Forked from Sniffnet v1.5.1 (`b235b9e`, 2026-09-19).

### Added

- `netwatchd`: a headless daemon for servers. Captures with libpcap, aggregates
  bidirectional flows (protocol, endpoints, packets, bytes, timestamps), and
  serves an embedded dashboard at `/` with JSON at `/api/stats` and a liveness
  probe at `/healthz`. No external assets, no CDN, no API keys.
- Binds to `127.0.0.1` by default so `tailscale serve` can publish it without
  exposing it on the LAN.
- `--demo` mode serves the dashboard with synthetic traffic, so the UI can be
  inspected before granting any privileges. The addresses are documentation
  ranges and the mode is reported as `demo`, so it cannot be mistaken for
  capture.
- Seven unit tests covering flow folding, per-direction accounting, key
  stability and up/down attribution. They run without any capture privileges,
  and CI runs them.
- `--list` enumerates capture interfaces.
- Errors are surfaced in the dashboard itself: a missing `CAP_NET_RAW` shows up
  in the UI with the exact `setcap` command rather than silently reporting zero
  traffic.

### Added

- Uptime history, daily traffic budgets, per-device notification rules and
  long-term retention, all in one pass:
  - `--history <PATH>` keeps a SQLite file (WAL, `synchronous=NORMAL`) with one
    row per device per UTC day — bytes each way, packets, seconds online,
    sessions — plus closed sessions. `--history-days` (default 365) bounds it.
    The keeper flushes once every 30 seconds in a single transaction, and only
    for devices whose counters moved, so the cost is proportional to devices and
    never to packets.
  - Each device carries a daily budget in gigabytes, set from its page. Crossing
    it raises one `quota_exceeded` alert for the day, from the same counter the
    page shows.
  - Each device carries its own rule for being interrupted: `default`, `quiet`
    (only what needs action) or `never`. The rule is applied where the alert is
    raised and recorded on the alert, so the dashboard and the spool keep every
    fact while the notifier skips what is marked `muted`.
  - `/api/history?days=30` serves the kept days and per-device uptime; the
    overview draws the last 30 days and each device page draws its own.
- `tools/netwatch-notify` gains a `quota_exceeded` label, an `include_muted`
  setting, and skips alerts a device's own rule kept quiet.

### Fixed

- Byte accounting in `attribute` used the transport payload length while the
  device totals used the frame length, so per-direction counters and therefore
  budgets silently counted less than the dashboard's own totals. Both now use
  one frame length, and a test covers it.
- The "ports it used" list recorded whichever end happened to be the source,
  which for a client meant its ephemeral port (51422) rather than the service it
  used (443). The port that is not an ephemeral client port is the one kept.
- A rejected write answered `200 OK` with an error body. It answers `400`.
- `--devices` was missing from the shipped unit, so a restart re-learned the
  whole network and re-announced it as new.

### Changed

- Renamed from Sniffnet to Netwatch throughout (see `NOTICE.md`).
- The vendored parser crate is now `netwatch-packet-parser`.
- Removed ~85 MB of unused upstream media from the working tree.

### Notes

- The desktop application is retained and unmodified in behaviour. Its rename is
  **compile-unverified** in this environment because building it requires
  `pkg-config` and the `libasound2-dev` headers, which are not installed here.
  It is not a GTK application and needs no fontconfig headers. See
  `docs/BUILDING.md`.
