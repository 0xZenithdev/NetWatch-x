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

## Running it as a service

**Without root — a user service.** Works with the `setcap` above, needs no
privileges to install, and survives logout because user services with lingering
enabled are started at boot:

```sh
mkdir -p ~/.config/systemd/user
cp packaging/netwatchd.service ~/.config/systemd/user/
# edit ExecStart to your interface and the absolute path of the binary
systemctl --user enable --now netwatchd.service
loginctl enable-linger "$USER"    # start it at boot, not at login
```

The trap: systemd sets `NoNewPrivileges=true` by default for services, and with
that flag the kernel **ignores file capabilities**. `setcap` succeeds, the
service starts, and it captures nothing. The unit in `packaging/` sets it to
`false` explicitly. If you write your own, do not omit it.

**With root — a system service (preferred).** It grants the capability to the
service, so there is no `setcap` step and a rebuild cannot strip it:

```sh
sudo install -m 644 packaging/netwatchd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netwatchd.service
```

Allow ~2 seconds before the dashboard has data.

## The desktop application (Sniffnet's original GUI)

On Debian:

```sh
sudo apt install pkg-config libpcap-dev libasound2-dev
cargo build
```

Three packages, and that is the whole list: `alsa-sys` is the only C library the
desktop app links that the daemon does not. GTK is not used (the GUI is
`winit`-based, not GTK), and `fontconfig-parser` — the only fontconfig entry in
`Cargo.lock` — is pure Rust and needs no system headers.
