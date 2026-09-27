# NOTICE

## This is a fork

Netwatch is a fork of **Sniffnet** — <https://github.com/GyulyVGC/sniffnet> —
Copyright (c) 2022-2026 Giuliano Bellini <gyulyvgc99@gmail.com>, dual-licensed
under the MIT and Apache-2.0 licences. Those licences are retained verbatim in
`LICENSE-MIT` and `LICENSE-APACHE`.

Portions copyright (c) 2026 0xZenithdev, for the modifications listed below.

## Modifications made by this fork

In accordance with Apache-2.0 §4(b), the changes are:

- **Renamed** the project, crates, binaries and user-facing strings from
  "sniffnet" to "netwatch", per Apache-2.0 §6 (no trademark rights are granted
  by the licence). Upstream's copyright notices are untouched.
- **Added `netwatchd`**, a headless daemon that captures flows and serves a
  browser dashboard, depending only on `pcap` and `etherparse`.
- **Removed** unused upstream media: `resources/logos/merch` (60 MB),
  `resources/fonts/full` (14 MB, unreferenced by the build), `resources/audits`,
  `resources/thesis.pdf` and `resources/repository/old`.
- **Renamed** the vendored packet-parser crate to `netwatch-packet-parser`.

## Bundled third-party assets

See `resources/packaging/linux/deb-source/debian/asset-notices.txt` for the
notices upstream ships (Sarasa Gothic font, SIL OFL 1.1; country flags from
HatScripts/circle-flags, MIT). Upstream's own `debian/copyright` records that
"source and license records are incomplete for some bundled assets, including
sounds, the icon font, MMDB databases and services.txt" — **that is still true
here and should be treated as outstanding work**, not as cleared.
