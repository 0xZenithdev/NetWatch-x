//! netwatchd — headless network flow monitor with a browser dashboard.
//!
//! Captures packets with libpcap, aggregates them into flows, and serves a small
//! dashboard over HTTP. Everything is embedded in this binary: no external
//! assets, no CDN, no API keys.
//!
//! Binds to 127.0.0.1 by default so `tailscale serve` can proxy to it without
//! exposing it on the LAN.
//!
//! Capture needs CAP_NET_RAW. Composing packets is not required and is never
//! done here — this is read-only monitoring.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use etherparse::{NetSlice, SlicedPacket, TransportSlice};

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
}

//──────────────────────────────────────────────────────────────── capture

fn friendly(msg: &str) -> String {
    let lower = msg.to_lowercase();
    if lower.contains("permission") || lower.contains("not permitted") || lower.contains("operation not permitted") {
        format!(
            "{msg}\n\nThis is the CAP_NET_RAW check. Grant it to this binary once:\n  \
             sudo setcap cap_net_raw,cap_net_admin=eip {}",
            std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<path to netwatchd>".into())
        )
    } else {
        msg.to_string()
    }
}

fn capture_loop(iface: String, state: Arc<Mutex<State>>) {
    let opened = pcap::Capture::from_device(iface.as_str())
        .and_then(|c| c.promisc(true).snaplen(SNAPLEN).timeout(250).open());
    // setnonblock() consumes and returns the handle, so it has to be rebound
    let mut cap = match opened.and_then(|c| c.setnonblock()) {
        Ok(c) => c,
        Err(e) => return set_error(&state, &friendly(&e.to_string())),
    };

    let mut last_stats = Instant::now();
    loop {
        match cap.next_packet() {
            Ok(packet) => ingest(packet.data, &state),
            Err(pcap::Error::NoMorePackets) => std::thread::sleep(Duration::from_millis(40)),
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => return set_error(&state, &friendly(&e.to_string())),
        }
        if last_stats.elapsed() >= Duration::from_secs(2) {
            if let Ok(st) = cap.stats() {
                if let Ok(mut s) = state.lock() {
                    s.kernel_dropped = st.dropped;
                    s.kernel_received = st.received;
                }
            }
            last_stats = Instant::now();
        }
    }
}

fn set_error(state: &Arc<Mutex<State>>, msg: &str) {
    if let Ok(mut s) = state.lock() {
        s.error = Some(msg.to_string());
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

    let len = data.len() as u64;
    let Ok(mut s) = state.lock() else { return };
    let now = s.started.elapsed().as_secs();
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
    let is_local = |e: &Endpoint| local_ips.iter().any(|ip| *ip == e.ip);
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
fn demo_traffic(state: Arc<Mutex<State>>) {
    const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    let peers = [
        (Ipv4Addr::new(192, 0, 2, 1), 443u16),
        (Ipv4Addr::new(198, 51, 100, 7), 443),
        (Ipv4Addr::new(203, 0, 113, 53), 53),
        (Ipv4Addr::new(198, 51, 100, 20), 80),
        (Ipv4Addr::new(203, 0, 113, 9), 853),
    ];
    let local = Endpoint { ip: IpAddr::V4(LOCAL), port: 0 };
    let mut n: u64 = 0;
    loop {
        std::thread::sleep(Duration::from_millis(350));
        let (peer_ip, peer_port) = peers[(n as usize) % peers.len()];
        let sleep_for = n;
        let peer = Endpoint { ip: IpAddr::V4(peer_ip), port: peer_port };
        let sport_endpoint = Endpoint { ip: local.ip, port: 40000 + (n % 900) as u16 };
        let now = match state.lock() {
            Ok(s) => s.started.elapsed().as_secs(),
            Err(_) => return,
        };
        if let Ok(mut s) = state.lock() {
            observe(&mut s, "TCP", sport_endpoint, peer, 128, now);
            observe(&mut s, "TCP", peer, sport_endpoint, 1400 + sleep_for % 9000, now);
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
                if let Some(desc) = d.desc {
                    if !desc.trim().is_empty() {
                        println!("  {:<16}   {}", "", desc.trim());
                    }
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
    flows.sort_by(|a, b| b.1.bytes().cmp(&a.1.bytes()));

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
    hosts.sort_by(|a, b| b.1.cmp(&a.1));
    let top_hosts: Vec<serde_json::Value> = hosts
        .into_iter()
        .take(12)
        .map(|(host, bytes)| serde_json::json!({ "host": host, "bytes": bytes }))
        .collect();

    serde_json::json!({
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

fn http_loop(listener: TcpListener, state: Arc<Mutex<State>>) {
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let st = state.clone();
                std::thread::spawn(move || handle(s, st));
            }
            Err(_) => continue,
        }
    }
}

fn handle(mut stream: TcpStream, state: Arc<Mutex<State>>) {
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
            Ok(0) => break,
            Ok(_) if h == "\r\n" || h == "\n" => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }

    let (code, ctype, body) = match path.as_str() {
        "/" | "/index.html" => ("200 OK", "text/html; charset=utf-8", DASHBOARD.to_string()),
        "/api/stats" => ("200 OK", "application/json", stats_json(&state)),
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

const DASHBOARD: &str = r##"<!doctype html>
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
"##;

//──────────────────────────────────────────────────────────────── main

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut iface: Option<String> = None;
    let mut bind = DEFAULT_BIND.to_string();
    let mut port = DEFAULT_PORT;
    let mut demo = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-i" | "--iface" => {
                iface = args.get(i + 1).cloned();
                i += 2;
            }
            "--bind" => {
                if let Some(v) = args.get(i + 1) {
                    bind = v.clone();
                }
                i += 2;
            }
            "-p" | "--port" => {
                if let Some(v) = args.get(i + 1).and_then(|v| v.parse().ok()) {
                    port = v;
                }
                i += 2;
            }
            "--demo" => {
                demo = true;
                i += 1;
            }
            "--list" => {
                list_ifaces();
                return;
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                return;
            }
            other => {
                eprintln!("unknown argument: {other}\n\n{USAGE}");
                std::process::exit(2);
            }
        }
    }

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
    }));

    if demo {
        println!("netwatchd in demo mode: synthetic traffic, nothing is captured");
        let st = state.clone();
        std::thread::spawn(move || demo_traffic(st));
    } else {
        let st = state.clone();
        let name = chosen.clone();
        std::thread::spawn(move || capture_loop(name, st));
    }

    let addr = format!("{bind}:{port}");
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot bind {addr}: {e}");
            std::process::exit(1);
        }
    };
    println!("netwatchd listening on http://{addr}  (interface: {chosen})");
    http_loop(listener, state);
}

#[cfg(test)]
mod tests {
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
}
