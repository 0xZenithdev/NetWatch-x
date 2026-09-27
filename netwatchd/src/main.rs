// netwatchd is a command-line daemon: writing to stdout and stderr is its
// interface. The workspace denies that, which is correct for the GUI binary where
// a stray println! is a bug, and wrong here. Cargo does not allow a member to
// both inherit the workspace lints and override them, so the exception lives
// here. Everything else, including the full pedantic set, still applies.
#![allow(clippy::print_stdout, clippy::print_stderr)]

//! netwatchd — headless network flow monitor with a browser dashboard.
//!
//! Captures packets with libpcap, aggregates them into flows, and serves a small
//! dashboard over HTTP. Everything is embedded in this binary: no external
//! assets, no CDN, no API keys.
//!
//! Binds to 127.0.0.1 by default so `tailscale serve` can proxy to it without
//! exposing it on the LAN.
//!
//! Capture needs `CAP_NET_RAW`. Composing packets is not required and is never
//! done here — this is read-only monitoring.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use etherparse::{LinkSlice, NetSlice, SlicedPacket, TransportSlice};

const DEFAULT_BIND: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 8790;
const SNAPLEN: i32 = 128; // headers only: we count, we do not collect payloads

const USAGE: &str = "\
netwatchd — headless network flow monitor

USAGE:
    netwatchd [OPTIONS]

OPTIONS:
    -i, --iface <NAME>   interface to capture on (default: first non-loopback)
        --bind <ADDR>    address to serve on (default: 127.0.0.1)
    -p, --port <PORT>    port to serve on (default: 8790)
        --demo           serve the dashboard without capturing anything
        --list           list available interfaces and exit
        --alerts <PATH>  append alerts as JSON lines to PATH
        --test-alert     append one test alert and exit, to prove delivery works
        --devices <PATH> remember devices across restarts, so a crash or an
                         upgrade does not re-announce every device as new
    -h, --help           show this help

NOTE:
    Capturing requires CAP_NET_RAW. Without it the dashboard still runs and will
    tell you exactly what to do about it.";

//──────────────────────────────────────────────────────────────── state

/// One end of a conversation. Ordered so the two ends can be put in a canonical
/// order, which is what makes aggregation bidirectional: the reply updates the
/// same entry as the request instead of inventing a second flow.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
struct Endpoint {
    ip: IpAddr,
    port: u16,
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct FlowKey {
    proto: &'static str,
    /// The lower of the two endpoints. Never the "source": a key that depended
    /// on who spoke first would split every conversation in two.
    a: Endpoint,
    b: Endpoint,
}

#[derive(Default, Clone)]
struct Flow {
    ab_packets: u64,
    ab_bytes: u64,
    ba_packets: u64,
    ba_bytes: u64,
    first_seen: u64,
    last_seen: u64,
}

impl Flow {
    fn packets(&self) -> u64 {
        self.ab_packets + self.ba_packets
    }
    fn bytes(&self) -> u64 {
        self.ab_bytes + self.ba_bytes
    }
}

struct State {
    iface: String,
    mode: &'static str,
    started: Instant,
    flows: HashMap<FlowKey, Flow>,
    packets: u64,
    bytes: u64,
    kernel_dropped: u32,
    kernel_received: u32,
    error: Option<String>,
    note: Option<String>,
    /// Addresses of the interface being captured, used to tell "up" from "down".
    local_ips: Vec<IpAddr>,
    /// Most recent alerts, newest last.
    alerts: Vec<Alert>,
    /// Where alerts are appended, if anywhere.
    alert_sink: Option<std::path::PathBuf>,
    /// Hosts seen on the wire, keyed by MAC.
    devices: HashMap<[u8; 6], Device>,
}

//──────────────────────────────────────────────────────────────── devices

/// A host seen on the wire, identified by its MAC.
#[derive(Clone)]
struct Device {
    mac: [u8; 6],
    ips: Vec<IpAddr>,
    first_seen: u64,
    last_seen: u64,
    packets: u64,
    bytes: u64,
    online: bool,
}

/// A device that keeps changing address would otherwise grow this list without
/// limit; eight is far more than an honest host needs.
const MAX_IPS_PER_DEVICE: usize = 8;
/// How long a device may be silent before it is called offline.
const DEVICE_IDLE_SECS: u64 = 300;

fn mac_string(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Addresses that can belong to a host on this network: private IPv4,
/// link-local, IPv6 unique-local and IPv6 link-local.
///
/// `172.67.219.2` and `172.217.112.4` are Cloudflare and Google, not private
/// addresses — only 172.16.0.0/12 is — which is exactly the mistake live
/// traffic caught here.
fn is_lan_address(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let head = v6.segments()[0];
            head & 0xfe00 == 0xfc00 || head & 0xffc0 == 0xfe80
        }
    }
}

/// MACs that cannot belong to a host: broadcast, multicast, or all zero.
fn is_host_mac(mac: [u8; 6]) -> bool {
    mac != [0u8; 6] && mac[0] & 1 == 0
}

/// Record a sighting of a device, raising an alert the first time a MAC is seen.
///
/// A MAC that has never been seen before means a device joined the network;
/// noticing that is the core of an intruder detector, and because this box is
/// the gateway it gets the sighting for free, from traffic it was already
/// handling. Nothing has to be scanned, so nothing is disturbed on the LAN.
fn learn_device(s: &mut State, mac: [u8; 6], ip: IpAddr, len: u64, now: u64) {
    if !is_host_mac(mac) {
        return;
    }
    // A MAC may only be paired with an address on this LAN, in either direction.
    // On traffic to or from the internet the peer MAC is the router, so pairing
    // it with a remote address credits the router with every server the house
    // talks to — which is what happened before this check existed.
    if !is_lan_address(&ip) {
        return;
    }
    // Our own addresses are not a device worth reporting.
    if s.local_ips.contains(&ip) {
        return;
    }
    if let Some(d) = s.devices.get_mut(&mac) {
        d.last_seen = now;
        d.packets += 1;
        d.bytes += len;
        d.online = true;
        if !d.ips.contains(&ip) && d.ips.len() < MAX_IPS_PER_DEVICE {
            d.ips.push(ip);
        }
        return;
    }
    s.devices.insert(
        mac,
        Device {
            mac,
            ips: vec![ip],
            first_seen: now,
            last_seen: now,
            packets: 1,
            bytes: len,
            online: true,
        },
    );
    emit_alert(
        s,
        "new_device",
        "alert",
        &mac_string(mac),
        &format!("{ip} — first sighting on this network"),
    );
}

/// Retire devices that have gone quiet. A device that stops transmitting is
/// worth knowing about, and one that returns is worth knowing about too.
fn sweep_devices(s: &mut State, now: u64) {
    let mut went_offline = Vec::new();
    for d in s.devices.values_mut() {
        if d.online && now.saturating_sub(d.last_seen) > DEVICE_IDLE_SECS {
            d.online = false;
            went_offline.push(mac_string(d.mac));
        }
    }
    for mac in went_offline {
        emit_alert(
            s,
            "device_offline",
            "notable",
            &mac,
            &format!("no traffic for over {DEVICE_IDLE_SECS}s"),
        );
    }
}

/// Keep the device inventory alive: load what was remembered, retire devices
/// that have gone quiet, and write the inventory back so a restart does not
/// re-announce every device on the network.
fn spawn_device_keeper(state: Arc<Mutex<State>>, devices: Option<std::path::PathBuf>) {
    if let Some(path) = &devices {
        let known = match state.lock() {
            Ok(mut s) => load_devices(path, &mut s),
            Err(_) => 0,
        };
        println!("devices: {known} known from {}", path.display());
    }
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(30));
        let now = match state.lock() {
            Ok(s) => s.started.elapsed().as_secs(),
            Err(_) => return,
        };
        if let Ok(mut s) = state.lock() {
            sweep_devices(&mut s, now);
            if let Some(path) = &devices
                && let Err(e) = save_devices(path, &s)
            {
                eprintln!("could not save devices: {e}");
            }
        }
    });
}

/// Parse `aa:bb:cc:dd:ee:ff`.
fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = text.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

/// Write the inventory where a restart can find it, atomically so a crash
/// mid-write cannot leave a half-file behind.
fn save_devices(path: &std::path::Path, s: &State) -> std::io::Result<()> {
    let rows: Vec<serde_json::Value> = s
        .devices
        .values()
        .map(|d| {
            serde_json::json!({
                "mac": mac_string(d.mac),
                "ips": d.ips.iter().map(ToString::to_string).collect::<Vec<String>>(),
                "first_seen": d.first_seen,
                "last_seen": d.last_seen,
                "packets": d.packets,
                "bytes": d.bytes,
            })
        })
        .collect();
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec(&rows).unwrap_or_default())?;
    std::fs::rename(&tmp, path)
}

/// Load a previously written inventory. Without this a restart re-announces
/// every device on the network as new, which is an alert storm on any crash —
/// exactly the moment an operator is least willing to be shouted at.
///
/// Loaded devices are treated as already known, so they are not announced
/// again. They start offline and come online on their next frame.
fn load_devices(path: &std::path::Path, s: &mut State) -> usize {
    let Ok(text) = std::fs::read_to_string(path) else {
        return 0;
    };
    let Ok(rows) = serde_json::from_str::<Vec<serde_json::Value>>(&text) else {
        return 0;
    };
    let mut loaded = 0;
    for row in rows {
        let Some(mac) = row.get("mac").and_then(|v| v.as_str()).and_then(parse_mac) else {
            continue;
        };
        let ips: Vec<IpAddr> = row
            .get("ips")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .filter_map(|x| x.parse().ok())
                    .collect()
            })
            .unwrap_or_default();
        let num = |key: &str| row.get(key).and_then(serde_json::Value::as_u64).unwrap_or(0);
        s.devices.insert(
            mac,
            Device {
                mac,
                ips,
                first_seen: num("first_seen"),
                last_seen: num("last_seen"),
                packets: num("packets"),
                bytes: num("bytes"),
                online: false,
            },
        );
        loaded += 1;
    }
    loaded
}

//──────────────────────────────────────────────────────────────── alerts

/// An event worth telling a human about.
///
/// Alerts are held in memory for the API and appended to a spool file that a
/// separate notifier delivers. Keeping delivery out of this process means the
/// daemon needs no HTTP or TLS stack at all, and a Telegram outage can never
/// stall packet capture.
#[derive(Clone)]
struct Alert {
    ts: u64,
    kind: &'static str,
    severity: &'static str,
    subject: String,
    detail: String,
}

/// How many alerts stay in memory (and therefore in the API payload).
const ALERT_MEMORY: usize = 200;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Alert {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ts": self.ts,
            "kind": self.kind,
            "severity": self.severity,
            "subject": self.subject,
            "detail": self.detail,
        })
    }
}

/// Append one alert as a single JSON line.
///
/// One line per alert is deliberate: a torn write can lose the alert being
/// written but cannot corrupt the ones already spooled, and a tailing reader
/// never has to parse a half-written record.
fn append_alert(path: &std::path::Path, a: &Alert) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(f, "{}", a.to_json())
}

fn write_test_alert(path: &std::path::Path) -> std::io::Result<()> {
    append_alert(
        path,
        &Alert {
            ts: now_unix(),
            kind: "test",
            severity: "info",
            subject: "netwatchd test alert".into(),
            detail: "If you received this, the alert path works end to end.".into(),
        },
    )
}

/// Record an alert in memory and spool it. A failure to write the spool must
/// never take down the caller: the alert is still in memory and in the API.
fn emit_alert(s: &mut State, kind: &'static str, severity: &'static str, subject: &str, detail: &str) {
    let a = Alert {
        ts: now_unix(),
        kind,
        severity,
        subject: subject.to_string(),
        detail: detail.to_string(),
    };
    if let Some(path) = &s.alert_sink {
        let _ = append_alert(path, &a);
    }
    s.alerts.push(a);
    let len = s.alerts.len();
    if len > ALERT_MEMORY {
        s.alerts.drain(0..len - ALERT_MEMORY);
    }
}

//──────────────────────────────────────────────────────────────── capture

fn friendly(msg: &str) -> String {
    let lower = msg.to_lowercase();
    if lower.contains("permission") || lower.contains("not permitted") || lower.contains("operation not permitted") {
        format!(
            "{msg}\n\nThis is the CAP_NET_RAW check. Grant it to this binary once:\n  \
             sudo setcap cap_net_raw,cap_net_admin=eip {}",
            std::env::current_exe().map_or_else(
                |_| "<path to netwatchd>".into(),
                |p| p.display().to_string(),
            )
        )
    } else {
        msg.to_string()
    }
}

fn capture_loop(iface: &str, state: &Arc<Mutex<State>>) {
    let opened = pcap::Capture::from_device(iface)
        .and_then(|c| c.promisc(true).snaplen(SNAPLEN).timeout(250).open());
    // setnonblock() consumes and returns the handle, so it has to be rebound
    let mut cap = match opened.and_then(pcap::Capture::setnonblock) {
        Ok(c) => c,
        Err(e) => return set_error(state, &friendly(&e.to_string())),
    };

    let mut last_stats = Instant::now();
    loop {
        match cap.next_packet() {
            Ok(packet) => ingest(packet.data, state),
            Err(pcap::Error::NoMorePackets) => std::thread::sleep(Duration::from_millis(40)),
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => return set_error(state, &friendly(&e.to_string())),
        }
        if last_stats.elapsed() >= Duration::from_secs(2) {
            // let-chain: both conditions have to hold before either value is used
            if let Ok(st) = cap.stats()
                && let Ok(mut s) = state.lock()
            {
                s.kernel_dropped = st.dropped;
                s.kernel_received = st.received;
            }
            last_stats = Instant::now();
        }
    }
}

fn set_error(state: &Arc<Mutex<State>>, msg: &str) {
    if let Ok(mut s) = state.lock() {
        s.error = Some(msg.to_string());
        // A monitor that has silently stopped monitoring is the worst failure
        // mode there is, so losing capture raises an alert and not just a note
        // on a dashboard nobody is looking at.
        emit_alert(&mut s, "capture_failed", "alert", "capture stopped", msg);
    }
}

fn ingest(data: &[u8], state: &Arc<Mutex<State>>) {
    let Ok(pkt) = SlicedPacket::from_ethernet(data) else {
        return;
    };
    let (src, dst) = match &pkt.net {
        Some(NetSlice::Ipv4(ip)) => (
            IpAddr::V4(Ipv4Addr::from(ip.header().source())),
            IpAddr::V4(Ipv4Addr::from(ip.header().destination())),
        ),
        Some(NetSlice::Ipv6(ip)) => (
            IpAddr::V6(Ipv6Addr::from(ip.header().source())),
            IpAddr::V6(Ipv6Addr::from(ip.header().destination())),
        ),
        _ => return,
    };
    let (proto, sport, dport) = match &pkt.transport {
        Some(TransportSlice::Tcp(t)) => ("TCP", t.source_port(), t.destination_port()),
        Some(TransportSlice::Udp(u)) => ("UDP", u.source_port(), u.destination_port()),
        _ => ("other", 0, 0),
    };

    // The Ethernet header identifies which host sent this; that is the whole
    // basis of device discovery here.
    let macs = match &pkt.link {
        Some(LinkSlice::Ethernet2(eth)) => Some((eth.source(), eth.destination())),
        _ => None,
    };

    let len = data.len() as u64;
    let Ok(mut s) = state.lock() else { return };
    let now = s.started.elapsed().as_secs();
    if let Some((src_mac, dst_mac)) = macs {
        // Both ends are real hosts on this LAN: the sender, and the receiver
        // (which is how a download-heavy device is noticed at all).
        learn_device(&mut s, src_mac, src, len, now);
        learn_device(&mut s, dst_mac, dst, len, now);
    }
    observe(
        &mut s,
        proto,
        Endpoint { ip: src, port: sport },
        Endpoint { ip: dst, port: dport },
        len,
        now,
    );
}

/// Fold one packet into the conversation it belongs to.
///
/// The endpoints are ordered before they become the key, so a request and its
/// reply share an entry and the direction is recorded in the counters rather
/// than by creating a second row. Pure state manipulation, no privileges
/// needed — which is exactly why it is separable from the capture loop.
fn observe(s: &mut State, proto: &'static str, src: Endpoint, dst: Endpoint, len: u64, now: u64) {
    let forward = (src.ip, src.port) <= (dst.ip, dst.port);
    let (a, b) = if forward { (src, dst) } else { (dst, src) };
    let entry = s.flows.entry(FlowKey { proto, a, b }).or_insert_with(|| Flow {
        first_seen: now,
        last_seen: now,
        ..Default::default()
    });
    if forward {
        entry.ab_packets += 1;
        entry.ab_bytes += len;
    } else {
        entry.ba_packets += 1;
        entry.ba_bytes += len;
    }
    entry.last_seen = now;
    s.packets += 1;
    s.bytes += len;
}

/// Which end of a conversation is this host, who is the peer, and how much went
/// each way. `None` for the local end means neither endpoint is ours — traffic
/// routed through rather than to us — in which case no up/down can be claimed.
fn orient(local_ips: &[IpAddr], k: &FlowKey, f: &Flow) -> (Option<Endpoint>, Endpoint, u64, u64) {
    let is_local = |e: &Endpoint| local_ips.contains(&e.ip);
    if is_local(&k.a) {
        (Some(k.a), k.b, f.ab_bytes, f.ba_bytes)
    } else if is_local(&k.b) {
        (Some(k.b), k.a, f.ba_bytes, f.ab_bytes)
    } else {
        (None, k.b, 0, 0)
    }
}

/// Fabricate conversations so the dashboard can be inspected without granting
/// any capability. Addresses are RFC 5737 documentation ranges, so nothing about
/// this machine's real network ends up in a public repository, and `mode` is
/// reported as "demo" so synthetic traffic can never be mistaken for capture.
fn demo_traffic(state: &Arc<Mutex<State>>) {
    const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    let peers = [
        (Ipv4Addr::new(192, 0, 2, 1), 443u16),
        (Ipv4Addr::new(198, 51, 100, 7), 443),
        (Ipv4Addr::new(203, 0, 113, 53), 53),
        (Ipv4Addr::new(198, 51, 100, 20), 80),
        (Ipv4Addr::new(203, 0, 113, 9), 853),
    ];
    // Plausible LAN hosts, so the device list and new-device alerts are
    // exercised in demo mode too — demo traffic never reaches the packet
    // parser, which is where real learning happens.
    let lan: [([u8; 6], Ipv4Addr); 3] = [
        ([0x02, 0x11, 0x22, 0x33, 0x44, 0x01], Ipv4Addr::new(192, 0, 2, 20)),
        ([0x02, 0x11, 0x22, 0x33, 0x44, 0x02], Ipv4Addr::new(192, 0, 2, 21)),
        ([0x02, 0x11, 0x22, 0x33, 0x44, 0x03], Ipv4Addr::new(192, 0, 2, 22)),
    ];
    let mut n: usize = 0;
    loop {
        std::thread::sleep(Duration::from_millis(350));
        let (peer_ip, peer_port) = peers[n % peers.len()];
        // try_from rather than `as`: the values are bounded by the modulus, and
        // this says so instead of truncating on a target with 32-bit pointers
        let offset = u16::try_from(n % 900).unwrap_or(0);
        let extra = u64::try_from(n % 9000).unwrap_or(0);
        let ours = Endpoint { ip: IpAddr::V4(LOCAL), port: 40000 + offset };
        let peer = Endpoint { ip: IpAddr::V4(peer_ip), port: peer_port };
        let now = match state.lock() {
            Ok(s) => s.started.elapsed().as_secs(),
            Err(_) => return,
        };
        if let Ok(mut s) = state.lock() {
            observe(&mut s, "TCP", ours, peer, 128, now);
            observe(&mut s, "TCP", peer, ours, 1400 + extra, now);
            let (mac, lan_ip) = lan[(n / 4) % lan.len()];
            learn_device(&mut s, mac, IpAddr::V4(lan_ip), 200 + extra, now);
        }
        n += 1;
    }
}

fn device_addresses(name: &str) -> Vec<IpAddr> {
    pcap::Device::list()
        .ok()
        .and_then(|ds| ds.into_iter().find(|d| d.name == name))
        .map(|d| d.addresses.into_iter().map(|a| a.addr).collect())
        .unwrap_or_default()
}

fn pick_device(wanted: Option<&str>) -> Result<String, String> {
    let devices = pcap::Device::list().map_err(|e| format!("cannot list interfaces: {e}"))?;
    if devices.is_empty() {
        return Err("no capture interfaces found".into());
    }
    if let Some(name) = wanted {
        return devices
            .iter()
            .find(|d| d.name == name)
            .map(|d| d.name.clone())
            .ok_or_else(|| format!("no interface named '{name}' (try --list)"));
    }
    devices
        .iter()
        .find(|d| d.addresses.iter().any(|a| !a.addr.is_loopback()))
        .or_else(|| devices.first())
        .map(|d| d.name.clone())
        .ok_or_else(|| "no usable interface found".into())
}

fn list_ifaces() {
    match pcap::Device::list() {
        Ok(devices) => {
            println!("capture interfaces:");
            for d in devices {
                let addrs: Vec<String> = d
                    .addresses
                    .iter()
                    .map(|a| a.addr.to_string())
                    .collect();
                println!(
                    "  {:<16} {}",
                    d.name,
                    if addrs.is_empty() { "-".to_string() } else { addrs.join(", ") }
                );
                if let Some(desc) = d.desc
                    && !desc.trim().is_empty()
                {
                    println!("  {:<16}   {}", "", desc.trim());
                }
            }
        }
        Err(e) => eprintln!("cannot list interfaces: {e}"),
    }
}

//──────────────────────────────────────────────────────────────── api

fn stats_json(state: &Arc<Mutex<State>>) -> String {
    let Ok(s) = state.lock() else {
        return "{\"error\":\"state poisoned\"}".into();
    };
    let mut flows: Vec<(&FlowKey, &Flow)> = s.flows.iter().collect();
    flows.sort_by_key(|a| std::cmp::Reverse(a.1.bytes()));

    let top_flows: Vec<serde_json::Value> = flows
        .iter()
        .take(60)
        .map(|(k, f)| {
            let (local, peer, up, down) = orient(&s.local_ips, k, f);
            serde_json::json!({
                "proto": k.proto,
                "a": k.a.to_string(),
                "b": k.b.to_string(),
                "local": local.map(|e| e.to_string()),
                "peer": peer.to_string(),
                "up_bytes": up, "down_bytes": down,
                "packets": f.packets(), "bytes": f.bytes(),
                "first_seen": f.first_seen, "last_seen": f.last_seen,
            })
        })
        .collect();

    let mut by_proto: HashMap<&str, u64> = HashMap::new();
    let mut by_host: HashMap<String, u64> = HashMap::new();
    for (k, f) in &flows {
        *by_proto.entry(k.proto).or_insert(0) += f.bytes();
        // Attribute volume to the far end only when we can tell which end that is.
        let remote = match orient(&s.local_ips, k, f).0 {
            Some(_) => orient(&s.local_ips, k, f).1.ip,
            None => continue,
        };
        if !remote.is_loopback() && !remote.is_unspecified() {
            *by_host.entry(remote.to_string()).or_insert(0) += f.bytes();
        }
    }
    let mut hosts: Vec<(String, u64)> = by_host.into_iter().collect();
    hosts.sort_by_key(|a| std::cmp::Reverse(a.1));
    let top_hosts: Vec<serde_json::Value> = hosts
        .into_iter()
        .take(12)
        .map(|(host, bytes)| serde_json::json!({ "host": host, "bytes": bytes }))
        .collect();

    let alerts: Vec<serde_json::Value> = s.alerts.iter().rev().take(50).map(Alert::to_json).collect();

    let mut devices: Vec<&Device> = s.devices.values().collect();
    devices.sort_by_key(|d| std::cmp::Reverse(d.last_seen));
    let devices: Vec<serde_json::Value> = devices
        .iter()
        .take(200)
        .map(|d| {
            serde_json::json!({
                "mac": mac_string(d.mac),
                "ips": d.ips.iter().map(ToString::to_string).collect::<Vec<String>>(),
                "first_seen": d.first_seen,
                "last_seen": d.last_seen,
                "packets": d.packets,
                "bytes": d.bytes,
                "online": d.online,
            })
        })
        .collect();

    serde_json::json!({
        "alerts": alerts,
        "alert_count": s.alerts.len(),
        "devices": devices,
        "device_count": s.devices.len(),
        "iface": s.iface,
        "mode": s.mode,
        "uptime_s": s.started.elapsed().as_secs(),
        "packets": s.packets,
        "bytes": s.bytes,
        "flows": s.flows.len(),
        "kernel_received": s.kernel_received,
        "kernel_dropped": s.kernel_dropped,
        "error": s.error,
        "note": s.note,
        "by_proto": by_proto,
        "top_hosts": top_hosts,
        "top_flows": top_flows,
    })
    .to_string()
}

//──────────────────────────────────────────────────────────────── http

fn http_loop(listener: &TcpListener, state: &Arc<Mutex<State>>) {
    // a failed accept is not fatal: skip it and keep serving
    for s in listener.incoming().flatten() {
        // each connection gets its own handle on the shared state
        let st = state.clone();
        std::thread::spawn(move || handle(s, &st));
    }
}

fn handle(mut stream: TcpStream, state: &Arc<Mutex<State>>) {
    let Ok(peek) = stream.try_clone() else { return };
    let mut reader = BufReader::new(peek);
    let mut request = String::new();
    if reader.read_line(&mut request).is_err() {
        return;
    }
    let path = request
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/")
        .to_string();
    // drain headers
    loop {
        let mut h = String::new();
        match reader.read_line(&mut h) {
            Ok(0) | Err(_) => break,
            Ok(_) if h == "\r\n" || h == "\n" => break,
            Ok(_) => {}
        }
    }

    let (code, ctype, body) = match path.as_str() {
        "/" | "/index.html" => ("200 OK", "text/html; charset=utf-8", DASHBOARD.to_string()),
        "/api/stats" => ("200 OK", "application/json", stats_json(state)),
        "/healthz" => ("200 OK", "text/plain", "ok".to_string()),
        "/favicon.ico" => ("204 No Content", "text/plain", String::new()),
        _ => ("404 Not Found", "text/plain", "not found".to_string()),
    };
    let response = format!(
        "HTTP/1.1 {code}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

//──────────────────────────────────────────────────────────────── ui

const DASHBOARD: &str = r#"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>netwatch</title>
<style>
  :root{--bg:#0d1117;--panel:#161b22;--line:#243040;--fg:#e6edf3;--dim:#8b949e;--acc:#58a6ff;--warn:#d29922;--bad:#f85149}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
  header{padding:14px 16px;border-bottom:1px solid var(--line);display:flex;flex-wrap:wrap;gap:8px;align-items:baseline}
  h1{font-size:16px;margin:0;letter-spacing:.3px}
  .tag{font-size:11px;color:var(--dim);border:1px solid var(--line);border-radius:999px;padding:1px 8px}
  main{padding:14px 16px 40px;max-width:1000px;margin:0 auto}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
  .card .k{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.6px}
  .card .v{font-size:20px;font-variant-numeric:tabular-nums;margin-top:2px}
  h2{font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:.8px;margin:22px 0 8px}
  .row{display:flex;justify-content:space-between;gap:10px;padding:7px 2px;border-bottom:1px solid var(--line);font-variant-numeric:tabular-nums}
  .row:last-child{border-bottom:0}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;word-break:break-all}
  .num{color:var(--dim);white-space:nowrap}
  .banner{border-radius:10px;padding:10px 12px;margin:14px 0;border:1px solid;white-space:pre-wrap;font-family:ui-monospace,Menlo,monospace;font-size:12px}
  .banner.err{background:#2d1418;border-color:#5c1f26;color:#ffb3ae}
  .banner.note{background:#2a2310;border-color:#5c4a12;color:#f0d38a}
  .muted{color:var(--dim)}
  footer{color:var(--dim);font-size:11px;padding:10px 16px 30px;text-align:center}
</style></head>
<body>
<header>
  <h1>netwatch</h1>
  <span class="tag" id="iface">…</span>
  <span class="tag" id="mode">…</span>
  <span class="tag" id="uptime">…</span>
</header>
<main>
  <div id="banners"></div>
  <div class="cards">
    <div class="card"><div class="k">packets</div><div class="v" id="pkts">0</div></div>
    <div class="card"><div class="k">volume</div><div class="v" id="bytes">0</div></div>
    <div class="card"><div class="k">flows</div><div class="v" id="flows">0</div></div>
    <div class="card"><div class="k">dropped</div><div class="v" id="dropped">0</div></div>
  </div>
  <h2>protocols</h2><div id="protos" class="muted">waiting for traffic…</div>
  <h2>top destinations</h2><div id="hosts" class="muted">waiting for traffic…</div>
  <h2>top flows</h2><div id="flowsbox" class="muted">waiting for traffic…</div>
</main>
<footer>netwatchd · read-only capture · no payloads stored</footer>
<script>
function hb(n){const u=["B","KB","MB","GB","TB"];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return (i?n.toFixed(1):n)+" "+u[i]}
function dur(s){const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return d?d+"d "+h+"h":h?h+"h "+m+"m":m?m+"m":"just started"}
function esc(x){return String(x).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]))}
async function tick(){
  let d;
  try{ d = await (await fetch("/api/stats",{cache:"no-store"})).json() }catch(e){ return }
  iface.textContent = "iface " + d.iface;
  mode.textContent = d.mode;
  uptime.textContent = dur(d.uptime_s||0);
  pkts.textContent = (d.packets||0).toLocaleString();
  bytes.textContent = hb(d.bytes||0);
  flows.textContent = (d.flows||0).toLocaleString();
  dropped.textContent = (d.kernel_dropped||0).toLocaleString();
  let b = "";
  if(d.error) b += '<div class="banner err">'+esc(d.error)+'</div>';
  if(d.mode==="demo") b += '<div class="banner note">demo mode — the traffic below is synthetic and nothing is being captured. Start without --demo, with CAP_NET_RAW, for real data.</div>';
  banners.innerHTML = b;
  const p = d.by_proto||{};
  const total = Object.values(p).reduce((a,c)=>a+c,0)||1;
  const pk = Object.entries(p).sort((a,b)=>b[1]-a[1]);
  protos.innerHTML = pk.length? pk.map(([k,v])=>'<div class="row"><span>'+esc(k)+'</span><span class="num">'+hb(v)+' · '+Math.round(v/total*100)+'%</span></div>').join("") : '<span class="muted">waiting for traffic…</span>';
  const hs = d.top_hosts||[];
  hosts.innerHTML = hs.length? hs.map(h=>'<div class="row"><span class="mono">'+esc(h.host)+'</span><span class="num">'+hb(h.bytes)+'</span></div>').join("") : '<span class="muted">waiting for traffic…</span>';
  const fs = (d.top_flows||[]).slice(0,40);
  flowsbox.innerHTML = fs.length? fs.map(f=>{
    const who = f.local ? '<span class="muted">↔</span> '+esc(f.peer) : esc(f.a)+' <span class="muted">↔</span> '+esc(f.b);
    const dir = f.local ? '<span class="muted">↑</span>'+hb(f.up_bytes)+' <span class="muted">↓</span>'+hb(f.down_bytes) : f.packets+' pkts';
    return '<div class="row"><span class="mono">'+esc(f.proto)+' '+who+'</span><span class="num">'+hb(f.bytes)+' '+dir+'</span></div>';
  }).join("") : '<span class="muted">waiting for traffic…</span>';
}
tick(); setInterval(tick, 2000);
</script>
</body></html>
"#;

//──────────────────────────────────────────────────────────────── main

/// Everything the command line can configure.
#[derive(Default)]
struct Config {
    iface: Option<String>,
    bind: Option<String>,
    port: Option<u16>,
    demo: bool,
    alerts: Option<std::path::PathBuf>,
    devices: Option<std::path::PathBuf>,
    test_alert: bool,
}

/// Parse arguments.
///
/// `Ok(None)` means the requested work is already done — `--help` and `--list`
/// print and return — and an unknown flag is an error rather than something to
/// ignore, because a typo silently running the daemon unconfigured is worse
/// than refusing to start.
fn parse_args(args: &[String]) -> Result<Option<Config>, String> {
    let mut c = Config::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-i" | "--iface" => {
                c.iface = args.get(i + 1).cloned();
                i += 2;
            }
            "--bind" => {
                c.bind = args.get(i + 1).cloned();
                i += 2;
            }
            "-p" | "--port" => {
                c.port = args.get(i + 1).and_then(|v| v.parse().ok());
                i += 2;
            }
            "--demo" => {
                c.demo = true;
                i += 1;
            }
            "--alerts" => {
                c.alerts = args.get(i + 1).map(std::path::PathBuf::from);
                i += 2;
            }
            "--devices" => {
                c.devices = args.get(i + 1).map(std::path::PathBuf::from);
                i += 2;
            }
            "--test-alert" => {
                c.test_alert = true;
                i += 1;
            }
            "--list" => {
                list_ifaces();
                return Ok(None);
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(None);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Some(c))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = match parse_args(&args) {
        Ok(Some(c)) => c,
        Ok(None) => return,
        Err(e) => {
            eprintln!("{e}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    let Config { iface, bind, port, demo, alerts, devices, test_alert } = cfg;
    let bind = bind.unwrap_or_else(|| DEFAULT_BIND.to_string());
    let port = port.unwrap_or(DEFAULT_PORT);

    let chosen = if demo {
        iface.unwrap_or_else(|| "demo".to_string())
    } else {
        match pick_device(iface.as_deref()) {
            Ok(name) => name,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    };

    if test_alert {
        let path = alerts.unwrap_or_else(|| std::path::PathBuf::from("alerts.jsonl"));
        match write_test_alert(&path) {
            Ok(()) => {
                println!("wrote one test alert to {}", path.display());
                return;
            }
            Err(e) => {
                eprintln!("cannot write {}: {e}", path.display());
                std::process::exit(1);
            }
        }
    }

    let local_ips = if demo {
        vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]
    } else {
        device_addresses(&chosen)
    };
    let state = Arc::new(Mutex::new(State {
        iface: chosen.clone(),
        mode: if demo { "demo" } else { "live" },
        started: Instant::now(),
        flows: HashMap::new(),
        packets: 0,
        bytes: 0,
        kernel_dropped: 0,
        kernel_received: 0,
        error: None,
        note: None,
        local_ips,
        alerts: Vec::new(),
        alert_sink: alerts,
        devices: HashMap::new(),
    }));

    if demo {
        println!("netwatchd in demo mode: synthetic traffic, nothing is captured");
        let st = state.clone();
        std::thread::spawn(move || demo_traffic(&st));
    } else {
        let st = state.clone();
        let name = chosen.clone();
        std::thread::spawn(move || capture_loop(&name, &st));
    }

    spawn_device_keeper(Arc::clone(&state), devices);

    let addr = format!("{bind}:{port}");
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot bind {addr}: {e}");
            std::process::exit(1);
        }
    };
    println!("netwatchd listening on http://{addr}  (interface: {chosen})");
    http_loop(&listener, &state);
}

#[cfg(test)]
mod tests {
    // expect() is how a test states what it assumes; a broken assumption should
    // panic and name itself. The workspace denies it in shipped code, where a
    // panic is not an acceptable outcome.
    #![allow(clippy::expect_used)]

    use super::*;

    fn state(local: &[&str]) -> State {
        State {
            iface: "test0".into(),
            mode: "live",
            started: Instant::now(),
            flows: HashMap::new(),
            packets: 0,
            bytes: 0,
            kernel_dropped: 0,
            kernel_received: 0,
            error: None,
            note: None,
            local_ips: local.iter().map(|s| s.parse().expect("test ip")).collect(),
            alerts: Vec::new(),
            alert_sink: None,
            devices: HashMap::new(),
        }
    }

    fn ep(addr: &str, port: u16) -> Endpoint {
        Endpoint { ip: addr.parse().expect("test ip"), port }
    }

    #[test]
    fn a_reply_folds_into_the_same_conversation() {
        let mut s = state(&["10.0.0.5"]);
        observe(&mut s, "TCP", ep("10.0.0.5", 52344), ep("1.1.1.1", 443), 100, 0);
        observe(&mut s, "TCP", ep("1.1.1.1", 443), ep("10.0.0.5", 52344), 900, 1);
        assert_eq!(s.flows.len(), 1, "the reply must not open a second flow");
        let f = s.flows.values().next().expect("one flow");
        assert_eq!(f.packets(), 2);
        assert_eq!(f.bytes(), 1000);
        assert_eq!((s.packets, s.bytes), (2, 1000));
    }

    #[test]
    fn direction_is_counted_not_duplicated() {
        let mut s = state(&["10.0.0.5"]);
        // 10.0.0.5:52344 sorts above 1.1.1.1:443, so the first packet is b->a
        observe(&mut s, "TCP", ep("10.0.0.5", 52344), ep("1.1.1.1", 443), 100, 0);
        observe(&mut s, "TCP", ep("1.1.1.1", 443), ep("10.0.0.5", 52344), 900, 1);
        let f = s.flows.values().next().expect("one flow");
        assert_eq!((f.ab_bytes, f.ba_bytes), (900, 100));
        assert_eq!((f.ab_packets, f.ba_packets), (1, 1));
    }

    #[test]
    fn flow_identity_does_not_depend_on_who_spoke_first() {
        let mut first = state(&[]);
        let mut second = state(&[]);
        observe(&mut first, "UDP", ep("9.9.9.9", 53), ep("10.0.0.5", 33000), 60, 0);
        observe(&mut second, "UDP", ep("10.0.0.5", 33000), ep("9.9.9.9", 53), 60, 0);
        assert_eq!(
            first.flows.keys().next().expect("a flow"),
            second.flows.keys().next().expect("a flow"),
            "the same conversation seen from either side must key identically"
        );
    }

    #[test]
    fn protocols_do_not_share_a_conversation() {
        let mut s = state(&[]);
        observe(&mut s, "TCP", ep("1.1.1.1", 443), ep("10.0.0.5", 1), 10, 0);
        observe(&mut s, "UDP", ep("1.1.1.1", 443), ep("10.0.0.5", 1), 10, 0);
        assert_eq!(s.flows.len(), 2);
    }

    #[test]
    fn up_is_whatever_leaves_this_host() {
        let mut s = state(&["192.168.10.200"]);
        observe(&mut s, "TCP", ep("192.168.10.200", 51000), ep("93.184.216.34", 443), 500, 0);
        observe(&mut s, "TCP", ep("93.184.216.34", 443), ep("192.168.10.200", 51000), 1500, 1);
        let (k, f) = s.flows.iter().next().expect("one flow");
        let (local, peer, up, down) = orient(&s.local_ips, k, f);
        assert_eq!(local.expect("local end").to_string(), "192.168.10.200:51000");
        assert_eq!(peer.to_string(), "93.184.216.34:443");
        assert_eq!((up, down), (500, 1500), "up is egress");
        assert_eq!(f.bytes(), 2000);
    }

    #[test]
    fn traffic_that_is_not_ours_claims_no_direction() {
        let mut s = state(&["10.0.0.5"]);
        observe(&mut s, "TCP", ep("1.1.1.1", 1), ep("8.8.8.8", 2), 10, 0);
        let (k, f) = s.flows.iter().next().expect("one flow");
        let (local, _, up, down) = orient(&s.local_ips, k, f);
        assert!(local.is_none(), "neither end is us, so neither is local");
        assert_eq!((up, down), (0, 0), "no up/down may be invented");
    }

    #[test]
    fn counters_accumulate_across_packets() {
        let mut s = state(&["10.0.0.5"]);
        for i in 0..10 {
            observe(&mut s, "TCP", ep("10.0.0.5", 40000), ep("1.1.1.1", 80), 100, i);
        }
        let f = s.flows.values().next().expect("one flow");
        assert_eq!(f.packets(), 10);
        assert_eq!(f.bytes(), 1000);
        assert_eq!(f.first_seen, 0);
        assert_eq!(f.last_seen, 9);
    }

    fn ip(addr: &str) -> IpAddr {
        addr.parse().expect("test ip")
    }

    fn mac6(last: u8) -> [u8; 6] {
        [0x02, 0x00, 0x00, 0x00, 0x00, last]
    }

    #[test]
    fn a_restart_does_not_re_announce_the_network() {
        let dir = std::env::temp_dir().join(format!("nw-dev-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("devices.json");

        let mut first = state(&["192.168.10.200"]);
        learn_device(&mut first, mac6(1), ip("192.168.10.50"), 100, 0);
        learn_device(&mut first, mac6(2), ip("192.168.10.51"), 200, 0);
        assert_eq!(first.alerts.len(), 2);
        save_devices(&path, &first).expect("inventory saved");

        // A fresh process, as after a restart or an upgrade.
        let mut second = state(&["192.168.10.200"]);
        assert_eq!(load_devices(&path, &mut second), 2);
        assert!(second.alerts.is_empty(), "a restart must not re-announce known devices");
        assert_eq!(second.devices[&mac6(1)].bytes, 100);
        assert!(!second.devices[&mac6(1)].online, "offline until it speaks again");

        learn_device(&mut second, mac6(1), ip("192.168.10.50"), 5, 10);
        assert!(second.devices[&mac6(1)].online, "it comes back on its next frame");
        assert!(second.alerts.is_empty(), "a known device returning is not news");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_damaged_inventory_is_skipped_not_fatal() {
        let dir = std::env::temp_dir().join(format!("nw-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("devices.json");
        std::fs::write(
            &path,
            r#"[{"mac": "not-a-mac", "ips": ["192.168.10.9"]},
                {"mac": "02:00:00:00:00:0a", "ips": ["192.168.10.9", "garbage"], "packets": 3},
                {"no_mac_at_all": true}]"#,
        )
        .expect("wrote");
        let mut s = state(&["192.168.10.200"]);
        assert_eq!(load_devices(&path, &mut s), 1, "only the usable row is loaded");
        assert_eq!(s.devices[&mac6(0x0a)].ips, vec![ip("192.168.10.9")], "bad addresses dropped");
        assert_eq!(s.devices[&mac6(0x0a)].packets, 3);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn only_lan_addresses_can_identify_a_host() {
        assert!(is_lan_address(&ip("192.168.10.243")), "a real host on this LAN");
        assert!(is_lan_address(&ip("10.0.0.5")), "10/8 is private");
        assert!(is_lan_address(&ip("172.16.5.5")), "172.16/12 is private");
        assert!(is_lan_address(&ip("169.254.1.1")), "link-local");
        assert!(is_lan_address(&ip("fd00::1")), "IPv6 unique-local");
        assert!(is_lan_address(&ip("fe80::1")), "IPv6 link-local");
        assert!(!is_lan_address(&ip("149.154.167.92")), "Telegram is remote");
        assert!(!is_lan_address(&ip("172.67.219.2")), "Cloudflare: 172.67 is NOT private");
        assert!(!is_lan_address(&ip("172.217.112.4")), "Google: 172.217 is NOT private");
        assert!(!is_lan_address(&ip("8.8.8.8")), "a public resolver");
    }

    #[test]
    fn a_next_hop_mac_cannot_collect_remote_addresses() {
        let mut s = state(&["192.168.10.200"]);
        let router = mac6(7);
        // Traffic to the internet arrives with the router's MAC and a remote
        // address; that pair must be refused in both directions.
        learn_device(&mut s, router, ip("149.154.167.92"), 10, 0);
        learn_device(&mut s, router, ip("172.67.219.2"), 10, 0);
        assert!(s.devices.is_empty(), "the router must not be credited with remote servers");

        // The same MAC with a LAN address is the genuine host.
        learn_device(&mut s, router, ip("192.168.10.1"), 10, 0);
        assert_eq!(s.devices[&router].ips, vec![ip("192.168.10.1")]);
        assert_eq!(s.alerts.len(), 1, "and it is announced when it is really identified");
    }

    #[test]
    fn a_new_device_is_announced_exactly_once() {
        let mut s = state(&["192.168.10.200"]);
        let m = mac6(1);
        learn_device(&mut s, m, ip("192.168.10.50"), 100, 0);
        learn_device(&mut s, m, ip("192.168.10.50"), 200, 5);
        assert_eq!(s.devices.len(), 1);
        let announced: Vec<&Alert> = s.alerts.iter().filter(|a| a.kind == "new_device").collect();
        assert_eq!(announced.len(), 1, "a second sighting must not re-announce the device");
        assert_eq!(announced[0].severity, "alert");
        let d = s.devices.get(&m).expect("device recorded");
        assert_eq!((d.packets, d.bytes), (2, 300));
        assert_eq!(d.last_seen, 5);
    }

    #[test]
    fn broadcast_and_multicast_macs_are_not_devices() {
        let mut s = state(&["192.168.10.200"]);
        learn_device(&mut s, [0xff; 6], ip("192.168.10.50"), 10, 0);
        learn_device(&mut s, [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01], ip("224.0.0.1"), 10, 0);
        learn_device(&mut s, [0x00; 6], ip("192.168.10.51"), 10, 0);
        assert!(s.devices.is_empty(), "broadcast, multicast and the null MAC are not hosts");
    }

    #[test]
    fn our_own_addresses_are_not_reported_as_devices() {
        let mut s = state(&["192.168.10.200"]);
        learn_device(&mut s, mac6(9), ip("192.168.10.200"), 10, 0);
        assert!(s.devices.is_empty(), "the monitor is not a device on its own LAN");
    }

    #[test]
    fn a_silent_device_is_retired_and_alerted_once() {
        let mut s = state(&["192.168.10.200"]);
        let m = mac6(2);
        learn_device(&mut s, m, ip("192.168.10.60"), 10, 0);
        sweep_devices(&mut s, DEVICE_IDLE_SECS - 1);
        assert!(s.devices[&m].online, "inside the window it is still online");
        sweep_devices(&mut s, DEVICE_IDLE_SECS + 1);
        assert!(!s.devices[&m].online);
        assert_eq!(
            s.alerts.iter().filter(|a| a.kind == "device_offline").count(),
            1,
            "retiring a device alerts once"
        );
        sweep_devices(&mut s, DEVICE_IDLE_SECS + 120);
        assert_eq!(
            s.alerts.iter().filter(|a| a.kind == "device_offline").count(),
            1,
            "and does not keep alerting on every sweep"
        );
    }

    #[test]
    fn a_device_that_returns_is_online_again() {
        let mut s = state(&["192.168.10.200"]);
        let m = mac6(3);
        learn_device(&mut s, m, ip("192.168.10.61"), 10, 0);
        sweep_devices(&mut s, DEVICE_IDLE_SECS + 1);
        assert!(!s.devices[&m].online);
        learn_device(&mut s, m, ip("192.168.10.61"), 10, DEVICE_IDLE_SECS + 10);
        assert!(s.devices[&m].online, "traffic means it is back");
    }

    #[test]
    fn a_device_cannot_collect_addresses_without_limit() {
        let mut s = state(&["192.168.10.200"]);
        let m = mac6(4);
        for i in 0..40 {
            learn_device(&mut s, m, ip(&format!("192.168.10.{}", 100 + i)), 10, 0);
        }
        assert_eq!(s.devices[&m].ips.len(), MAX_IPS_PER_DEVICE);
    }

    #[test]
    fn arguments_are_parsed_or_refused() {
        let ok = parse_args(&[
            "--iface".into(),
            "eth0".into(),
            "--port".into(),
            "9000".into(),
            "--demo".into(),
        ])
        .expect("valid arguments")
        .expect("a config, not early return");
        assert_eq!(ok.iface.as_deref(), Some("eth0"));
        assert_eq!(ok.port, Some(9000));
        assert!(ok.demo);
        assert!(parse_args(&["--nonsense".into()]).is_err(), "a typo must be an error");
        assert!(
            parse_args(&["--help".into()]).expect("help is fine").is_none(),
            "--help does its work and returns"
        );
    }

    #[test]
    fn alerts_reach_both_memory_and_the_spool() {
        let path = std::env::temp_dir().join(format!("netwatch-alerts-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut s = state(&[]);
        s.alert_sink = Some(path.clone());
        emit_alert(&mut s, "new_device", "alert", "aa:bb:cc:dd:ee:ff", "192.168.10.42 first seen");
        assert_eq!(s.alerts.len(), 1);
        assert_eq!(s.alerts[0].kind, "new_device");
        assert_eq!(s.alerts[0].severity, "alert");
        let body = std::fs::read_to_string(&path).expect("spool readable");
        let v: serde_json::Value = serde_json::from_str(body.lines().next().expect("one line")).expect("valid json");
        assert_eq!(v["kind"], "new_device");
        assert!(v["ts"].as_u64().unwrap_or(0) > 0, "alerts carry a wall-clock timestamp");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_spool_is_append_only_one_line_per_alert() {
        let path = std::env::temp_dir().join(format!("netwatch-spool-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        for _ in 0..3 {
            write_test_alert(&path).expect("write");
        }
        let body = std::fs::read_to_string(&path).expect("spool readable");
        assert_eq!(body.lines().count(), 3);
        for line in body.lines() {
            serde_json::from_str::<serde_json::Value>(line).expect("every line stands alone");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn alert_memory_is_bounded_and_keeps_the_newest() {
        let mut s = state(&[]);
        for i in 0..(ALERT_MEMORY + 25) {
            emit_alert(&mut s, "new_device", "alert", "x", &i.to_string());
        }
        assert_eq!(s.alerts.len(), ALERT_MEMORY, "memory must not grow without limit");
        let newest = &s.alerts[s.alerts.len() - 1];
        assert_eq!(newest.detail, (ALERT_MEMORY + 24).to_string(), "newest survive, oldest are dropped");
    }
}
