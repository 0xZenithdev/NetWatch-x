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
- `--demo` mode serves the dashboard without capturing, so the UI can be
  inspected before granting any privileges.
- `--list` enumerates capture interfaces.
- Errors are surfaced in the dashboard itself: a missing `CAP_NET_RAW` shows up
  in the UI with the exact `setcap` command rather than silently reporting zero
  traffic.

### Changed

- Renamed from Sniffnet to Netwatch throughout (see `NOTICE.md`).
- The vendored parser crate is now `netwatch-packet-parser`.
- Removed ~85 MB of unused upstream media from the working tree.

### Notes

- The desktop application is retained and unmodified in behaviour. Its rename is
  **compile-unverified** in this environment because building it requires the
  GTK/ALSA/fontconfig development headers, which are not installed here. See
  `docs/BUILDING.md`.
