# Building Netwatch

Two targets live in this workspace, with different requirements.

## netwatchd — the headless daemon (recommended, minimal deps)

Needs `pcap` and `etherparse` only. No GTK, no ALSA, no fontconfig.

```sh
cargo build -p netwatchd
```

The linker needs a `libpcap.so` to resolve `-lpcap`. Many distributions ship the
runtime libraries only, which is enough to *run* but not to *link*. If the link
fails with `cannot find -lpcap`, either install the development package:

```sh
sudo apt install pkg-config libpcap-dev
```

or point the linker at a symlink in your home directory (no root):

```sh
mkdir -p ~/.local/lib
ln -sf /usr/lib/x86_64-linux-gnu/libpcap.so.1.10.5 ~/.local/lib/libpcap.so
```

and add to `.cargo/config.toml` in this directory:

```toml
[build]
rustflags = ["-L", "native=/home/<you>/.local/lib"]
```

## Running it

Capturing needs `CAP_NET_RAW`. It is a read-only monitoring capability: Netwatch
never composes or injects packets. Grant it once to the built binary:

```sh
sudo setcap cap_net_raw,cap_net_admin=eip target/debug/netwatchd
target/debug/netwatchd --iface eth0
```

Note that rebuilding replaces the binary and therefore drops the capability, so
re-run `setcap` after each build — or install it as a systemd *system* unit with
`AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`, which survives rebuilds.

Without the capability the daemon still starts and serves the dashboard, and the
dashboard states what is wrong.

## The desktop application (Sniffnet's original GUI)

Requires the full upstream toolchain — on Debian:

```sh
sudo apt install pkg-config libpcap-dev libasound2-dev libfontconfig1-dev
cargo build
```
