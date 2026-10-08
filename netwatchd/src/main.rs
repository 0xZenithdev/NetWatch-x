// netwatchd is a command-line daemon: writing to stdout and stderr is its
// interface. The workspace denies that, which is correct for the GUI binary where
// a stray println! is a bug, and wrong here. Cargo does not allow a member to
// both inherit the workspace lints and override them, so the exception lives
// here. Everything else, including the full pedantic set, still applies.
#![allow(clippy::print_stdout, clippy::print_stderr)]

//! netwatchd — a headless network flow monitor with a browser dashboard.
//!
//! Captures packets with libpcap, aggregates them into flows, learns which
//! devices are on the network, and serves a dashboard over HTTP. Everything is
//! embedded in this binary: no external assets, no CDN, no API keys, no LLM.
//!
//! Binds to 127.0.0.1 by default so `tailscale serve` can proxy to it without
//! exposing it on the LAN.
//!
//! Capture needs `CAP_NET_RAW`. Composing packets is not required and is never
//! done here — this is read-only monitoring.

mod alerts;
mod api;
mod capture;
mod devices;
mod history;
mod http;
mod oui;
mod state;
mod store;

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use state::State;

const DEFAULT_BIND: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 8790;
/// How often devices are retired, series sampled and the inventory considered.
const SWEEP_SECS: u64 = 30;
/// How often a changed inventory is written to disk. Every sweep would be a few
/// hundred kilobytes every thirty seconds, which on a homelab disk is a lot of
/// writes for state that changes slowly. An operator edit is saved immediately
/// instead, because that one is a decision rather than an observation.
const SAVE_SECS: u64 = 600;

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
        --devices <PATH> remember devices across restarts, so a crash or an
                         upgrade does not re-announce every device as new
                         (default: devices.json beside --alerts)
        --history <PATH> keep the long-term record in a SQLite file: one row per
                         device per day, plus sessions, so uptime and volume are
                         still there next month (default: history.db beside
                         --devices; pass an empty value to switch it off)
        --history-days <N> how many days to keep (default: 365)
        --no-dns-names   do not read domain names out of plaintext DNS; the
                         device list then shows addresses only
        --test-alert     append one test alert and exit, to prove delivery works
    -V, --version        print the version and exit
    -h, --help           show this help

NOTE:
    Capturing requires CAP_NET_RAW. Without it the dashboard still runs and will
    tell you exactly what to do about it.

PRIVACY:
    The capture snapshot is 128 bytes, so payloads are not retained. The single
    exception is that the *name* in a plaintext DNS query is read, because it is
    the only way to say what a device is doing; nothing else is looked at, and
    --no-dns-names turns even that off.";

/// Everything the command line can configure.
#[derive(Default)]
struct Config {
    iface: Option<String>,
    bind: Option<String>,
    port: Option<u16>,
    demo: bool,
    alerts: Option<std::path::PathBuf>,
    devices: Option<std::path::PathBuf>,
    history: Option<std::path::PathBuf>,
    history_days: Option<u64>,
    dns_names: bool,
    test_alert: bool,
}

/// Parse arguments.
///
/// `Ok(None)` means the requested work is already done — `--help`, `--list` and
/// `--version` print and return — and an unknown flag is an error rather than
/// something to ignore, because a typo silently running the daemon unconfigured
/// is worse than refusing to start.
fn parse_args(args: &[String]) -> Result<Option<Config>, String> {
    let mut c = Config {
        dns_names: true,
        ..Config::default()
    };
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
            "--history" => {
                // An empty value switches retention off, which is a real choice
                // on a box with a small disk.
                c.history = match args.get(i + 1).map(String::as_str) {
                    Some("") => None,
                    Some(path) => Some(std::path::PathBuf::from(path)),
                    None => Some(std::path::PathBuf::from("history.db")),
                };
                i += 2;
            }
            "--history-days" => {
                c.history_days = args.get(i + 1).and_then(|v| v.parse().ok());
                i += 2;
            }
            "--no-dns-names" => {
                c.dns_names = false;
                i += 1;
            }
            "--test-alert" => {
                c.test_alert = true;
                i += 1;
            }
            "--list" => {
                capture::list_ifaces();
                return Ok(None);
            }
            "-V" | "--version" => {
                println!("netwatchd {}", env!("CARGO_PKG_VERSION"));
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
    let Some(cfg) = config_or_exit() else {
        return;
    };
    let bind = cfg.bind.clone().unwrap_or_else(|| DEFAULT_BIND.to_string());
    let port = cfg.port.unwrap_or(DEFAULT_PORT);
    let chosen = pick_interface(&cfg);

    if cfg.test_alert {
        let path = cfg
            .alerts
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("alerts.jsonl"));
        match alerts::write_test_alert(&path) {
            Ok(()) => println!("wrote one test alert to {}", path.display()),
            Err(e) => {
                eprintln!("cannot write {}: {e}", path.display());
                std::process::exit(1);
            }
        }
        return;
    }

    let local_ips = if cfg.demo {
        vec![IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 10, 200))]
    } else {
        capture::device_addresses(&chosen)
    };
    // The device store defaults to sitting beside the alert spool: a deployment
    // that asked for alerts has a state directory, and losing the inventory on
    // every restart is the bug this prevents.
    let device_store = cfg.devices.clone().or_else(|| {
        cfg.alerts
            .as_ref()
            .map(|p| p.with_file_name("devices.json"))
    });
    // Retention sits beside the inventory unless told otherwise.
    let history_path = cfg.history.clone().or_else(|| {
        device_store
            .as_ref()
            .map(|p| p.with_file_name("history.db"))
    });
    let history = match &history_path {
        Some(path) => match history::History::open(
            path,
            cfg.history_days.unwrap_or(history::DEFAULT_KEEP_DAYS),
        ) {
            Ok(h) => Some(Arc::new(Mutex::new(h))),
            Err(e) => {
                // Retention is a nice-to-have; capture is the job. Say so and
                // carry on rather than refusing to start.
                eprintln!("history: {e} — continuing without long-term records");
                None
            }
        },
        None => None,
    };

    let state = Arc::new(Mutex::new(initial_state(
        &cfg,
        &chosen,
        local_ips,
        device_store.clone(),
        history.clone(),
        history_path.clone(),
    )));
    announce_inventory(&state, device_store.as_ref());
    if let (Some(hist), Some(path)) = (&history, &history_path)
        && let (Ok(mut s), Ok(h)) = (state.lock(), hist.lock())
    {
        let restored = history::restore_today(&h, &mut s, state::now_unix()).unwrap_or(0);
        println!(
            "history: keeping {} days in {} ({restored} devices continue today's totals)",
            h.keep_days(),
            path.display()
        );
    }

    if cfg.demo {
        println!("netwatchd in demo mode: synthetic traffic, nothing is captured");
        let st = Arc::clone(&state);
        std::thread::spawn(move || capture::demo_traffic(&st));
    } else {
        let st = Arc::clone(&state);
        let name = chosen.clone();
        std::thread::spawn(move || capture::capture_loop(&name, &st));
    }
    spawn_keeper(Arc::clone(&state), history);

    let addr = format!("{bind}:{port}");
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot bind {addr}: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "netwatchd listening on http://{addr}  (interface: {chosen}, mode: {})",
        capture::mode_of(cfg.demo).as_str()
    );
    http::http_loop(&listener, &state);
}

/// Read the command line. `None` means help was asked for and printed; a bad
/// argument prints the usage and exits, because a daemon that starts with half
/// an argument set is worse than one that refuses to start.
fn config_or_exit() -> Option<Config> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&args) {
        Ok(Some(c)) => Some(c),
        Ok(None) => None,
        Err(e) => {
            eprintln!("{e}\n\n{USAGE}");
            std::process::exit(2);
        }
    }
}

/// Which interface to read, or the demo pseudo-interface.
fn pick_interface(cfg: &Config) -> String {
    if cfg.demo {
        return cfg.iface.clone().unwrap_or_else(|| "demo".to_string());
    }
    match capture::pick_device(cfg.iface.as_deref()) {
        Ok(name) => name,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

/// The shared state, assembled before any thread is looking at it.
fn initial_state(
    cfg: &Config,
    chosen: &str,
    local_ips: Vec<IpAddr>,
    device_store: Option<PathBuf>,
    history: Option<Arc<Mutex<history::History>>>,
    history_path: Option<PathBuf>,
) -> State {
    State {
        iface: chosen.to_string(),
        mode: capture::mode_of(cfg.demo),
        started_at: state::now_unix(),
        started: Instant::now(),
        flows: HashMap::new(),
        packets: 0,
        bytes: 0,
        kernel_dropped: 0,
        kernel_received: 0,
        error: None,
        note: None,
        local_ips,
        alerts: VecDeque::new(),
        alert_sink: cfg.alerts.clone(),
        device_store,
        history,
        history_path,
        devices: HashMap::new(),
        ip_owners: HashMap::new(),
        hostnames: HashMap::new(),
        series: state::Series::default(),
        dirty: false,
        read_dns_names: cfg.dns_names,
    }
}

/// Load the remembered inventory, and say plainly whether it is being kept — an
/// operator who does not know their device names survived a restart will re-name
/// everything "just to be safe".
fn announce_inventory(state: &Arc<Mutex<State>>, device_store: Option<&PathBuf>) {
    let Some(path) = device_store else {
        println!("devices: no --devices path, so the inventory will be re-learned on restart");
        return;
    };
    let known = match state.lock() {
        Ok(mut s) => store::load_devices(path, &mut s),
        Err(_) => 0,
    };
    println!("devices: {known} remembered from {}", path.display());
}

/// Retire silent devices, sample the throughput series, and persist the
/// inventory now and then.
///
/// One thread does all three because they are all "every thirty seconds"
/// work, and a monitor that spawns a thread per chore is a monitor nobody can
/// reason about.
fn spawn_keeper(state: Arc<Mutex<State>>, history: Option<Arc<Mutex<history::History>>>) {
    std::thread::spawn(move || {
        let mut last_save = state::now_unix();
        // Session transitions, which only the keeper can see: it is the one
        // place that knows how long ago the last sweep was.
        let mut tracker = history::Tracker::default();
        let mut last_tick = state::now_unix();
        let mut failed_flushes: u32 = 0;
        loop {
            std::thread::sleep(Duration::from_secs(SWEEP_SECS));
            let now = state::now_unix();
            let elapsed = now.saturating_sub(last_tick);
            last_tick = now;
            let mut save_now = false;
            if let Ok(mut s) = state.lock() {
                devices::sweep_devices(&mut s, now);
                let (packets, bytes) = (s.packets, s.bytes);
                s.series.sample(packets, bytes, now);
                s.trim_flows();
                s.trim_hostnames();
                if s.dirty && now.saturating_sub(last_save) >= SAVE_SECS {
                    save_now = true;
                }
            }
            // Retention: one lock, one transaction, per sweep. The work is
            // proportional to the number of devices, never to the packets, and
            // a device that moved nothing since the last flush is skipped.
            if let Some(hist) = &history {
                let (mut s, mut h) = (state.lock(), hist.lock());
                if let (Ok(s), Ok(h)) = (&mut s, &mut h) {
                    match history::flush(s, h, &mut tracker, now, elapsed) {
                        Ok(_) => {
                            failed_flushes = 0;
                        }
                        Err(e) => {
                            // Loud once, then quiet: a full disk would otherwise
                            // fill the journal with the same sentence.
                            failed_flushes = failed_flushes.saturating_add(1);
                            if failed_flushes == 1 || failed_flushes.is_multiple_of(20) {
                                eprintln!("history: {e}");
                            }
                        }
                    }
                }
            }
            if save_now {
                if let Ok(mut s) = state.lock() {
                    match &s.device_store {
                        Some(path) => match store::save_devices(path, &s) {
                            Ok(()) => s.dirty = false,
                            Err(e) => {
                                // A failed save is reported and retried next
                                // sweep; it must never stop the monitor.
                                drop(s);
                                eprintln!("could not save the device inventory: {e}");
                                continue;
                            }
                        },
                        None => s.dirty = false,
                    }
                }
                last_save = now;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    // expect() and unwrap() are how a test states what it assumes; a broken
    // assumption should panic and name itself. The workspace denies them in
    // shipped code, where a panic is not an acceptable outcome.
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::devices::{Kind, Trust};
    use crate::state::{Endpoint, MAX_FLOWS};

    /// Filename extension, compared without case because a download tool may
    /// well have lowercased nothing at all.
    fn has_extension(name: &str, want: &str) -> bool {
        std::path::Path::new(name)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case(want))
    }

    fn state(local: &[&str]) -> State {
        State {
            iface: "test0".into(),
            mode: state::Mode::Live,
            started_at: state::now_unix(),
            started: Instant::now(),
            flows: HashMap::new(),
            packets: 0,
            bytes: 0,
            kernel_dropped: 0,
            kernel_received: 0,
            error: None,
            note: None,
            local_ips: local.iter().map(|s| s.parse().expect("test ip")).collect(),
            alerts: VecDeque::new(),
            alert_sink: None,
            device_store: None,
            history: None,
            history_path: None,
            devices: HashMap::new(),
            ip_owners: HashMap::new(),
            hostnames: HashMap::new(),
            series: state::Series::default(),
            dirty: false,
            read_dns_names: true,
        }
    }

    fn ep(addr: &str, port: u16) -> Endpoint {
        Endpoint {
            ip: addr.parse().expect("test ip"),
            port,
        }
    }

    fn ip(addr: &str) -> IpAddr {
        addr.parse().expect("test ip")
    }

    fn mac6(last: u8) -> [u8; 6] {
        [0x02, 0x00, 0x00, 0x00, 0x00, last]
    }

    /// A globally unique (not locally administered) address, so vendor lookups
    /// behave the way they do for real hardware.
    fn real_mac(last: u8) -> [u8; 6] {
        [0x04, 0xea, 0x56, 0x00, 0x00, last]
    }

    fn alert_kinds(s: &State, kind: &str) -> usize {
        s.alerts.iter().filter(|a| a.kind == kind).count()
    }

    //────────────────────────────────── flows

    #[test]
    fn a_reply_folds_into_the_same_conversation() {
        let mut s = state(&["10.0.0.5"]);
        s.observe("TCP", ep("10.0.0.5", 52344), ep("1.1.1.1", 443), 100, 0);
        s.observe("TCP", ep("1.1.1.1", 443), ep("10.0.0.5", 52344), 900, 1);
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
        s.observe("TCP", ep("10.0.0.5", 52344), ep("1.1.1.1", 443), 100, 0);
        s.observe("TCP", ep("1.1.1.1", 443), ep("10.0.0.5", 52344), 900, 1);
        let f = s.flows.values().next().expect("one flow");
        assert_eq!((f.ab_bytes, f.ba_bytes), (900, 100));
        assert_eq!((f.ab_packets, f.ba_packets), (1, 1));
    }

    #[test]
    fn flow_identity_does_not_depend_on_who_spoke_first() {
        let mut first = state(&[]);
        let mut second = state(&[]);
        first.observe("UDP", ep("9.9.9.9", 53), ep("10.0.0.5", 33000), 60, 0);
        second.observe("UDP", ep("10.0.0.5", 33000), ep("9.9.9.9", 53), 60, 0);
        assert_eq!(
            first.flows.keys().next().expect("a flow"),
            second.flows.keys().next().expect("a flow"),
            "the same conversation seen from either side must key identically"
        );
    }

    #[test]
    fn protocols_do_not_share_a_conversation() {
        let mut s = state(&[]);
        s.observe("TCP", ep("1.1.1.1", 443), ep("10.0.0.5", 1), 10, 0);
        s.observe("UDP", ep("1.1.1.1", 443), ep("10.0.0.5", 1), 10, 0);
        assert_eq!(s.flows.len(), 2);
    }

    #[test]
    fn up_is_whatever_leaves_this_host() {
        let mut s = state(&["192.168.10.200"]);
        s.observe(
            "TCP",
            ep("192.168.10.200", 51000),
            ep("93.184.216.34", 443),
            500,
            0,
        );
        s.observe(
            "TCP",
            ep("93.184.216.34", 443),
            ep("192.168.10.200", 51000),
            1500,
            1,
        );
        let (k, f) = s.flows.iter().next().expect("one flow");
        let (local, peer, up, down) = s.orient(k, f);
        assert_eq!(
            local.expect("local end").to_string(),
            "192.168.10.200:51000"
        );
        assert_eq!(peer.to_string(), "93.184.216.34:443");
        assert_eq!((up, down), (500, 1500), "up is egress");
        assert_eq!(f.bytes(), 2000);
    }

    #[test]
    fn traffic_that_is_not_ours_claims_no_direction() {
        let mut s = state(&["10.0.0.5"]);
        s.observe("TCP", ep("1.1.1.1", 1), ep("8.8.8.8", 2), 10, 0);
        let (k, f) = s.flows.iter().next().expect("one flow");
        let (local, _, up, down) = s.orient(k, f);
        assert!(local.is_none(), "neither end is us, so neither is local");
        assert_eq!((up, down), (0, 0), "no up/down may be invented");
    }

    #[test]
    fn counters_accumulate_across_packets() {
        let mut s = state(&["10.0.0.5"]);
        for i in 0..10 {
            s.observe("TCP", ep("10.0.0.5", 40000), ep("1.1.1.1", 80), 100, i);
        }
        let f = s.flows.values().next().expect("one flow");
        assert_eq!(f.packets(), 10);
        assert_eq!(f.bytes(), 1000);
        assert_eq!(f.first_seen, 0);
        assert_eq!(f.last_seen, 9);
    }

    #[test]
    fn the_flow_table_is_bounded_and_keeps_the_busy() {
        let mut s = state(&[]);
        for i in 0..(MAX_FLOWS + 500) {
            // A unique conversation each time: ports run out, so the address has to
            // carry the rest, and the test would silently build a tiny table
            // otherwise.
            let a = u16::try_from(1024 + (i % 60_000)).unwrap_or(1024);
            let octet = u8::try_from(i / 60_000).unwrap_or(1);
            s.observe(
                "TCP",
                ep(&format!("10.0.{octet}.1"), a),
                ep(&format!("10.0.{octet}.2"), a + 1),
                10,
                u64::try_from(i).unwrap_or(0),
            );
        }
        s.trim_flows();
        assert!(s.flows.len() < MAX_FLOWS + 500, "the table must be trimmed");
        assert!(
            s.flows.len() >= MAX_FLOWS / 2,
            "and must not throw away everything"
        );
    }

    //────────────────────────────────── devices

    #[test]
    fn a_restart_does_not_re_announce_the_network() {
        let dir = std::env::temp_dir().join(format!("nw-dev-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("devices.json");

        let mut first = state(&["192.168.10.200"]);
        devices::learn_device(&mut first, mac6(1), ip("192.168.10.50"), 100, 1_700_000_000);
        devices::learn_device(&mut first, mac6(2), ip("192.168.10.51"), 200, 1_700_000_000);
        assert_eq!(first.alerts.len(), 2);
        store::save_devices(&path, &first).expect("inventory saved");

        // A fresh process, as after a restart or an upgrade.
        let mut second = state(&["192.168.10.200"]);
        assert_eq!(store::load_devices(&path, &mut second), 2);
        assert!(
            second.alerts.is_empty(),
            "a restart must not re-announce known devices"
        );
        assert_eq!(second.devices[&mac6(1)].bytes, 100);
        assert!(
            !second.devices[&mac6(1)].online,
            "offline until it speaks again"
        );

        devices::learn_device(&mut second, mac6(1), ip("192.168.10.50"), 5, 1_700_000_100);
        assert!(
            second.devices[&mac6(1)].online,
            "it comes back on its next frame"
        );
        assert!(
            second.alerts.is_empty(),
            "a known device returning is not news"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_damaged_inventory_is_skipped_not_fatal() {
        let dir = std::env::temp_dir().join(format!("nw-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("devices.json");
        // The old, version 1 shape: a bare array with plain string addresses.
        std::fs::write(
            &path,
            r#"[{"mac": "not-a-mac", "ips": ["192.168.10.9"]},
                {"mac": "02:00:00:00:00:0a", "ips": ["192.168.10.9", "garbage"], "packets": 3},
                {"no_mac_at_all": true}]"#,
        )
        .expect("wrote");
        let mut s = state(&["192.168.10.200"]);
        assert_eq!(
            store::load_devices(&path, &mut s),
            1,
            "only the usable row is loaded"
        );
        assert_eq!(s.devices[&mac6(0x0a)].ips.len(), 1, "bad addresses dropped");
        assert_eq!(s.devices[&mac6(0x0a)].packets, 3);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn timestamps_from_the_old_relative_clock_are_not_shown_as_dates_in_1970() {
        let dir = std::env::temp_dir().join(format!("nw-clock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("devices.json");
        std::fs::write(
            &path,
            r#"[{"mac": "02:00:00:00:00:0b", "ips": ["192.168.10.9"], "first_seen": 1408, "last_seen": 143210}]"#,
        )
        .expect("wrote");
        let mut s = state(&["192.168.10.200"]);
        assert_eq!(store::load_devices(&path, &mut s), 1);
        let d = &s.devices[&mac6(0x0b)];
        assert_eq!(
            d.first_seen, 0,
            "an implausible stamp is dropped, not displayed"
        );
        assert_eq!(d.last_seen, 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_inventory_survives_a_round_trip_with_names_and_history() {
        let dir = std::env::temp_dir().join(format!("nw-round-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("devices.json");

        let mut s = state(&["192.168.10.200"]);
        devices::learn_device(&mut s, real_mac(1), ip("192.168.10.50"), 100, 1_700_000_000);
        devices::note_peer(
            &mut s,
            ip("192.168.10.50"),
            ip("93.184.216.34"),
            500,
            1_700_000_010,
        );
        devices::note_port(&mut s, ip("192.168.10.50"), 443, 500);
        devices::note_domain(&mut s, ip("192.168.10.50"), "example.com");
        devices::apply_edit(
            &mut s,
            real_mac(1),
            &devices::Edit {
                name: Some("Study PC".into()),
                kind: Some("desktop".into()),
                trust: Some("trusted".into()),
                notes: Some("wired".into()),
                quota_gb: Some("20".into()),
                notify: Some("quiet".into()),
            },
        )
        .expect("edit applies");
        store::save_devices(&path, &s).expect("saved");

        let mut loaded = state(&["192.168.10.200"]);
        assert_eq!(store::load_devices(&path, &mut loaded), 1);
        let d = &loaded.devices[&real_mac(1)];
        assert_eq!(d.name.as_deref(), Some("Study PC"));
        assert_eq!(d.kind, Some(Kind::Desktop));
        assert_eq!(d.trust, Trust::Trusted);
        assert_eq!(d.notes, "wired");
        assert_eq!(d.peers.len(), 1, "the peer history is kept");
        assert_eq!(d.ports.get(&443), Some(&500));
        assert_eq!(d.domains.get("example.com"), Some(&1));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn only_lan_addresses_can_identify_a_host() {
        assert!(
            devices::is_lan_address(&ip("192.168.10.243")),
            "a real host on this LAN"
        );
        assert!(devices::is_lan_address(&ip("10.0.0.5")), "10/8 is private");
        assert!(
            devices::is_lan_address(&ip("172.16.5.5")),
            "172.16/12 is private"
        );
        assert!(devices::is_lan_address(&ip("169.254.1.1")), "link-local");
        assert!(devices::is_lan_address(&ip("fd00::1")), "IPv6 unique-local");
        assert!(devices::is_lan_address(&ip("fe80::1")), "IPv6 link-local");
        assert!(
            !devices::is_lan_address(&ip("149.154.167.92")),
            "Telegram is remote"
        );
        assert!(
            !devices::is_lan_address(&ip("172.67.219.2")),
            "Cloudflare: 172.67 is NOT private"
        );
        assert!(
            !devices::is_lan_address(&ip("172.217.112.4")),
            "Google: 172.217 is NOT private"
        );
        assert!(
            !devices::is_lan_address(&ip("8.8.8.8")),
            "a public resolver"
        );
    }

    #[test]
    fn a_next_hop_mac_cannot_collect_remote_addresses() {
        let mut s = state(&["192.168.10.200"]);
        let router = mac6(7);
        // Traffic to the internet arrives with the router's MAC and a remote
        // address; that pair must be refused in both directions.
        devices::learn_device(&mut s, router, ip("149.154.167.92"), 10, 0);
        devices::learn_device(&mut s, router, ip("172.67.219.2"), 10, 0);
        assert!(
            s.devices.is_empty(),
            "the router must not be credited with remote servers"
        );

        // The same MAC with a LAN address is the genuine host.
        devices::learn_device(&mut s, router, ip("192.168.10.1"), 10, 0);
        assert_eq!(s.devices[&router].ips.len(), 1);
        assert_eq!(
            s.alerts.len(),
            1,
            "and it is announced when it is really identified"
        );
    }

    #[test]
    fn a_new_device_is_announced_exactly_once() {
        let mut s = state(&["192.168.10.200"]);
        let m = mac6(1);
        devices::learn_device(&mut s, m, ip("192.168.10.50"), 100, 0);
        devices::learn_device(&mut s, m, ip("192.168.10.50"), 200, 5);
        assert_eq!(s.devices.len(), 1);
        assert_eq!(
            alert_kinds(&s, "new_device"),
            1,
            "a second sighting must not re-announce"
        );
        let d = s.devices.get(&m).expect("device recorded");
        assert_eq!((d.packets, d.bytes), (2, 300));
        assert_eq!(d.last_seen, 5);
    }

    #[test]
    fn broadcast_and_multicast_macs_are_not_devices() {
        let mut s = state(&["192.168.10.200"]);
        devices::learn_device(&mut s, [0xff; 6], ip("192.168.10.50"), 10, 0);
        devices::learn_device(
            &mut s,
            [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01],
            ip("224.0.0.1"),
            10,
            0,
        );
        devices::learn_device(&mut s, [0x00; 6], ip("192.168.10.51"), 10, 0);
        assert!(
            s.devices.is_empty(),
            "broadcast, multicast and the null MAC are not hosts"
        );
    }

    #[test]
    fn our_own_addresses_are_not_reported_as_devices() {
        let mut s = state(&["192.168.10.200"]);
        devices::learn_device(&mut s, mac6(9), ip("192.168.10.200"), 10, 0);
        assert!(
            s.devices.is_empty(),
            "the monitor is not a device on its own LAN"
        );
    }

    #[test]
    fn a_device_cannot_collect_addresses_without_limit() {
        let mut s = state(&["192.168.10.200"]);
        let m = mac6(4);
        for i in 0..40 {
            devices::learn_device(&mut s, m, ip(&format!("192.168.10.{}", 100 + i)), 10, 0);
        }
        assert_eq!(s.devices[&m].ips.len(), state::MAX_IPS_PER_DEVICE);
    }

    #[test]
    fn the_inventory_is_bounded_and_keeps_named_devices() {
        let mut s = state(&["192.168.10.200"]);
        // Name one device, then flood the inventory past its ceiling.
        devices::learn_device(&mut s, real_mac(1), ip("192.168.10.50"), 10, 1_000);
        devices::apply_edit(
            &mut s,
            real_mac(1),
            &devices::Edit {
                name: Some("Keeper".into()),
                ..devices::Edit::default()
            },
        )
        .expect("named");
        for i in 0..(state::MAX_DEVICES + 20) {
            let b = u8::try_from(i % 250).unwrap_or(0);
            let c = u8::try_from(i / 250).unwrap_or(0);
            let addr = format!("10.{b}.{c}.7");
            devices::learn_device(&mut s, [0x02, b, 0x00, c, 0x00, 0x01], ip(&addr), 10, 2_000);
        }
        assert!(
            s.devices.len() <= state::MAX_DEVICES,
            "the inventory must be bounded"
        );
        assert_eq!(
            s.devices.get(&real_mac(1)).and_then(|d| d.name.as_deref()),
            Some("Keeper"),
            "a device the operator named is never evicted"
        );
    }

    //────────────────────────────────── alerts and suppression

    #[test]
    fn a_silent_device_is_retired_and_alerted_once_in_its_window() {
        let mut s = state(&["192.168.10.200"]);
        let m = mac6(2);
        let t0 = 1_700_000_000;
        devices::learn_device(&mut s, m, ip("192.168.10.60"), 10, t0);
        devices::sweep_devices(&mut s, t0 + state::VISUAL_IDLE_SECS - 1);
        assert!(s.devices[&m].online, "inside the window it is still online");
        devices::sweep_devices(&mut s, t0 + state::VISUAL_IDLE_SECS + 1);
        assert!(
            !s.devices[&m].online,
            "the dashboard shows it offline quickly"
        );
        assert_eq!(
            alert_kinds(&s, "device_offline"),
            0,
            "but 15 minutes of silence is what alerts"
        );
        devices::sweep_devices(&mut s, t0 + state::OFFLINE_ALERT_SECS + 1);
        assert_eq!(alert_kinds(&s, "device_offline"), 1, "the alert fires once");
        devices::sweep_devices(&mut s, t0 + state::OFFLINE_ALERT_SECS + 120);
        assert_eq!(
            alert_kinds(&s, "device_offline"),
            1,
            "and not again on every sweep"
        );
    }

    #[test]
    fn a_flapping_device_cannot_alert_more_than_once_per_re_arm_window() {
        let mut s = state(&["192.168.10.200"]);
        let m = mac6(3);
        let mut now = 1_700_000_000;
        devices::learn_device(&mut s, m, ip("192.168.10.61"), 10, now);
        // Ten minutes on, twenty minutes off, all day: the pattern that produced
        // 2,519 alerts on this network before the re-arm window existed.
        for _ in 0..24 {
            now += state::OFFLINE_ALERT_SECS + 60;
            devices::sweep_devices(&mut s, now);
            devices::learn_device(&mut s, m, ip("192.168.10.61"), 10, now);
            now += 600;
            devices::sweep_devices(&mut s, now);
        }
        let offline = alert_kinds(&s, "device_offline");
        assert!(
            offline <= 2,
            "a day of flapping must not produce an alert per flap (got {offline})"
        );
        assert!(
            offline >= 1,
            "but the device really was away, so it is mentioned once"
        );
    }

    #[test]
    fn a_device_that_returns_is_online_again() {
        let mut s = state(&["192.168.10.200"]);
        let m = mac6(5);
        devices::learn_device(&mut s, m, ip("192.168.10.62"), 10, 1_000);
        devices::sweep_devices(&mut s, 1_000 + state::VISUAL_IDLE_SECS + 1);
        assert!(!s.devices[&m].online);
        devices::learn_device(&mut s, m, ip("192.168.10.62"), 10, 2_000);
        assert!(s.devices[&m].online, "traffic means it is back");
    }

    #[test]
    fn an_ignored_device_is_never_alerted_about() {
        let mut s = state(&["192.168.10.200"]);
        let m = mac6(6);
        devices::learn_device(&mut s, m, ip("192.168.10.63"), 10, 1_700_000_000);
        assert_eq!(alert_kinds(&s, "new_device"), 1);
        devices::apply_edit(
            &mut s,
            m,
            &devices::Edit {
                trust: Some("ignored".into()),
                ..devices::Edit::default()
            },
        )
        .expect("ignored");
        let before = s.alerts.len();
        devices::sweep_devices(&mut s, 1_700_000_000 + state::OFFLINE_ALERT_SECS + 60);
        assert_eq!(
            s.alerts.len(),
            before,
            "muting a device silences it completely"
        );
    }

    #[test]
    fn two_devices_on_one_address_are_reported() {
        let mut s = state(&["192.168.10.200"]);
        let a = real_mac(1);
        let b = real_mac(2);
        devices::learn_device(&mut s, a, ip("192.168.10.70"), 10, 1_700_000_000);
        devices::learn_device(&mut s, b, ip("192.168.10.70"), 10, 1_700_000_100);
        assert_eq!(alert_kinds(&s, "mac_conflict"), 2, "both holders are named");
        let detail = s
            .alerts
            .iter()
            .find(|a| a.kind == "mac_conflict")
            .map(|a| a.detail.clone())
            .expect("an alert");
        assert!(
            detail.contains("192.168.10.70"),
            "the address is in the message"
        );
    }

    #[test]
    fn an_address_change_is_reported_only_for_a_known_device() {
        let mut s = state(&["192.168.10.200"]);
        let m = real_mac(3);
        devices::learn_device(&mut s, m, ip("192.168.10.80"), 10, 1_700_000_000);
        assert_eq!(
            alert_kinds(&s, "address_change"),
            0,
            "the first address is not a change"
        );
        devices::learn_device(&mut s, m, ip("192.168.10.81"), 10, 1_700_000_100);
        assert_eq!(alert_kinds(&s, "address_change"), 1);
        devices::learn_device(&mut s, m, ip("192.168.10.81"), 10, 1_700_000_200);
        assert_eq!(
            alert_kinds(&s, "address_change"),
            1,
            "seeing it again is not a change"
        );
    }

    #[test]
    fn an_unusual_volume_is_compared_against_the_device_itself() {
        let mut s = state(&["192.168.10.200"]);
        let m = real_mac(4);
        let mut now = 1_700_000_000;
        devices::learn_device(&mut s, m, ip("192.168.10.90"), 1_000, now);
        // An hour of ordinary traffic, one sighting per minute.
        for _ in 0..40 {
            now += 60;
            devices::learn_device(&mut s, m, ip("192.168.10.90"), 1_000, now);
            devices::sweep_devices(&mut s, now);
        }
        assert_eq!(
            alert_kinds(&s, "traffic_spike"),
            0,
            "steady traffic is not a spike"
        );
        // Then one enormous minute.
        now += 60;
        devices::learn_device(&mut s, m, ip("192.168.10.90"), 50_000_000, now);
        devices::sweep_devices(&mut s, now + 60);
        assert_eq!(
            alert_kinds(&s, "traffic_spike"),
            1,
            "a surge is mentioned once"
        );
        devices::sweep_devices(&mut s, now + 120);
        assert_eq!(alert_kinds(&s, "traffic_spike"), 1, "and not repeated");
    }

    #[test]
    fn alert_memory_is_bounded_and_keeps_the_newest() {
        let mut s = state(&[]);
        for i in 0..(alerts::ALERT_MEMORY + 25) {
            alerts::emit_alert(&mut s, "new_device", "alert", "x", &i.to_string());
        }
        assert_eq!(
            s.alerts.len(),
            alerts::ALERT_MEMORY,
            "memory must not grow without limit"
        );
        let newest = s.alerts.back().expect("one alert");
        assert_eq!(
            newest.detail,
            (alerts::ALERT_MEMORY + 24).to_string(),
            "newest survive"
        );
    }

    #[test]
    fn alerts_reach_both_memory_and_the_spool() {
        let path =
            std::env::temp_dir().join(format!("netwatch-alerts-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut s = state(&[]);
        s.alert_sink = Some(path.clone());
        alerts::emit_alert(
            &mut s,
            "new_device",
            "alert",
            "aa:bb:cc:dd:ee:ff",
            "192.168.10.42 first seen",
        );
        assert_eq!(s.alerts.len(), 1);
        let body = std::fs::read_to_string(&path).expect("spool readable");
        let v: serde_json::Value =
            serde_json::from_str(body.lines().next().expect("one line")).expect("valid json");
        assert_eq!(v["kind"], "new_device");
        assert!(
            v["ts"].as_u64().unwrap_or(0) > 0,
            "alerts carry a wall-clock timestamp"
        );
        assert!(
            v["why"].as_str().unwrap_or("").len() > 20,
            "every alert explains itself"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_spool_is_append_only_one_line_per_alert() {
        let path =
            std::env::temp_dir().join(format!("netwatch-spool-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        for _ in 0..3 {
            alerts::write_test_alert(&path).expect("write");
        }
        let body = std::fs::read_to_string(&path).expect("spool readable");
        assert_eq!(body.lines().count(), 3);
        for line in body.lines() {
            serde_json::from_str::<serde_json::Value>(line).expect("every line stands alone");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn every_alert_kind_explains_itself() {
        for kind in [
            "new_device",
            "device_offline",
            "device_back_online",
            "address_change",
            "mac_conflict",
            "new_peer",
            "traffic_spike",
            "capture_failed",
            "test",
        ] {
            let why = alerts::explain(kind);
            assert!(
                why.len() > 40,
                "{kind} needs a real explanation, got: {why}"
            );
            assert!(!why.contains("No explanation"), "{kind} is not covered");
        }
    }

    //────────────────────────────────── naming and review

    #[test]
    fn an_edit_names_a_device_and_takes_it_out_of_the_review_queue() {
        let mut s = state(&["192.168.10.200"]);
        let m = real_mac(5);
        devices::learn_device(&mut s, m, ip("192.168.10.99"), 10, 1_700_000_000);
        assert!(
            s.devices[&m].needs_review(),
            "a new device starts unreviewed"
        );
        devices::apply_edit(
            &mut s,
            m,
            &devices::Edit {
                name: Some("Front door camera".into()),
                ..devices::Edit::default()
            },
        )
        .expect("edit");
        let d = &s.devices[&m];
        assert_eq!(d.name.as_deref(), Some("Front door camera"));
        assert_eq!(d.trust, Trust::Known, "naming it is a review");
        assert!(!d.needs_review());
        assert!(s.dirty, "an edit must be marked for saving");
    }

    #[test]
    fn an_empty_name_clears_it_and_a_rubbish_edit_is_refused() {
        let mut s = state(&["192.168.10.200"]);
        let m = real_mac(6);
        devices::learn_device(&mut s, m, ip("192.168.10.98"), 10, 1_700_000_000);
        devices::apply_edit(
            &mut s,
            m,
            &devices::Edit {
                name: Some("Temp".into()),
                ..devices::Edit::default()
            },
        )
        .expect("set");
        devices::apply_edit(
            &mut s,
            m,
            &devices::Edit {
                name: Some(String::new()),
                ..devices::Edit::default()
            },
        )
        .expect("clear");
        assert!(
            s.devices[&m].name.is_none(),
            "an empty name clears the field"
        );

        let long = "x".repeat(devices::MAX_NAME_CHARS + 1);
        assert!(
            devices::apply_edit(
                &mut s,
                m,
                &devices::Edit {
                    name: Some(long),
                    ..devices::Edit::default()
                }
            )
            .is_err()
        );
        assert!(
            devices::apply_edit(
                &mut s,
                m,
                &devices::Edit {
                    kind: Some("toaster".into()),
                    ..devices::Edit::default()
                }
            )
            .is_err(),
            "an unknown kind is refused rather than stored"
        );
        assert!(
            devices::apply_edit(
                &mut s,
                m,
                &devices::Edit {
                    trust: Some("vibes".into()),
                    ..devices::Edit::default()
                }
            )
            .is_err()
        );
        assert!(
            devices::apply_edit(
                &mut s,
                mac6(200),
                &devices::Edit {
                    name: Some("ghost".into()),
                    ..devices::Edit::default()
                }
            )
            .is_err(),
            "an unknown device is an error, not a silent no-op"
        );
        assert!(
            devices::apply_edit(
                &mut s,
                m,
                &devices::Edit {
                    name: Some("bad\u{7}name".into()),
                    ..devices::Edit::default()
                }
            )
            .is_err(),
            "control characters are not a name"
        );
    }

    #[test]
    fn the_review_queue_lists_unreviewed_devices_newest_first() {
        let mut s = state(&["192.168.10.200"]);
        devices::learn_device(&mut s, real_mac(1), ip("192.168.10.10"), 10, 1_700_000_000);
        devices::learn_device(&mut s, real_mac(2), ip("192.168.10.11"), 10, 1_700_000_500);
        devices::apply_edit(
            &mut s,
            real_mac(1),
            &devices::Edit {
                name: Some("Named".into()),
                ..devices::Edit::default()
            },
        )
        .expect("named");
        let queue = devices::review_queue(&s);
        assert_eq!(
            queue,
            vec![real_mac(2)],
            "only the unreviewed device is queued"
        );
    }

    //────────────────────────────────── identification

    #[test]
    fn a_randomised_address_has_no_maker_and_is_flagged() {
        // 0x9a has the locally-administered bit set: a phone's private address.
        let phone = [0x9a, 0x23, 0x0a, 0x5a, 0x5f, 0xe4];
        assert!(devices::is_randomized(phone));
        assert!(
            oui::vendor_for(phone).is_none(),
            "a throwaway address has no registered maker"
        );
        assert!(
            !devices::is_randomized([0x04, 0xea, 0x56, 0x00, 0x00, 0x01]),
            "a burnt-in address is not randomised"
        );
    }

    #[test]
    fn a_real_prefix_resolves_to_its_registered_maker() {
        // 04:EA:56 is registered to Intel, and is what this network's box reports.
        assert_eq!(
            oui::vendor_for([0x04, 0xea, 0x56, 0x11, 0x22, 0x33]),
            Some("Intel Corporate")
        );
        assert!(
            oui::table_size() > 10_000,
            "the embedded registry is real, not a stub"
        );
    }

    /// A history database in the temporary directory, unique per test so the
    /// suite can run in parallel without two tests sharing a file.
    fn temp_history(name: &str) -> history::History {
        let path =
            std::env::temp_dir().join(format!("netwatch-test-{name}-{}.db", std::process::id()));
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
        history::History::open(&path, 30).expect("a history database")
    }

    #[test]
    fn a_frame_from_a_lan_device_is_credited_to_that_device() {
        let mut s = state(&["192.168.10.200"]);
        let mac = real_mac(1);
        devices::learn_device(&mut s, mac, ip("192.168.10.50"), 100, 1_700_000_000);
        // A frame the device sent to the internet, exactly as the wire hands it
        // over: the device is the source, the address is not ours.
        capture::attribute(
            &mut s,
            &capture::PacketFacts {
                src: ip("192.168.10.50"),
                dst: ip("8.8.8.8"),
                sport: 51000,
                dport: 443,
                len: 100,
                now: 1_700_000_001,
            },
            &[0u8; 100],
        );
        let d = &s.devices[&mac];
        assert_eq!(d.up_bytes, 100, "the sender is credited with its own bytes");
        assert_eq!(d.day.up, 100, "and today's counter says the same");
        assert!(d.ports.contains_key(&443), "the port is remembered");
        assert!(!d.peers.is_empty(), "the conversation is remembered");
        // And the answer coming back is credited to the same device, the other way.
        capture::attribute(
            &mut s,
            &capture::PacketFacts {
                src: ip("8.8.8.8"),
                dst: ip("192.168.10.50"),
                sport: 443,
                dport: 51000,
                len: 100,
                now: 1_700_000_002,
            },
            &[0u8; 100],
        );
        assert_eq!(s.devices[&mac].down_bytes, 100);
        assert_eq!(s.devices[&mac].day.down, 100);
        // Our own traffic belongs to nobody: it is this machine.
        capture::attribute(
            &mut s,
            &capture::PacketFacts {
                src: ip("192.168.10.200"),
                dst: ip("8.8.8.8"),
                sport: 40000,
                dport: 443,
                len: 100,
                now: 1_700_000_003,
            },
            &[0u8; 100],
        );
        assert_eq!(
            s.devices[&mac].up_bytes, 100,
            "our own traffic is not a device's"
        );
    }

    #[test]
    fn an_address_points_back_at_its_device() {
        let mut s = state(&["192.168.10.200"]);
        let mac = real_mac(1);
        devices::learn_device(&mut s, mac, ip("192.168.10.50"), 100, 1_700_000_000);
        assert_eq!(
            s.device_by_ip(ip("192.168.10.50")),
            Some(mac),
            "the index answers for a learned address"
        );
        assert_eq!(
            s.device_by_ip(ip("8.8.8.8")),
            None,
            "a stranger has no device"
        );
        assert_eq!(
            s.device_by_ip(ip("192.168.10.200")),
            None,
            "our own address belongs to no device"
        );
    }

    #[test]
    fn a_budget_is_parsed_exactly() {
        let mut s = state(&["192.168.10.200"]);
        let mac = real_mac(1);
        devices::learn_device(&mut s, mac, ip("192.168.10.50"), 100, 1_700_000_000);
        let set = |s: &mut State, value: &str| {
            devices::apply_edit(
                s,
                mac,
                &devices::Edit {
                    quota_gb: Some(value.into()),
                    ..devices::Edit::default()
                },
            )
        };
        set(&mut s, "5").expect("five gigabytes");
        assert_eq!(s.devices[&mac].quota_bytes, Some(5 * 1_073_741_824));
        set(&mut s, "1.5").expect("one and a half");
        assert_eq!(
            s.devices[&mac].quota_bytes,
            Some(1_610_612_736),
            "1 GiB plus five tenths of a GiB, exactly"
        );
        set(&mut s, "0").expect("zero is a valid way to say no budget");
        assert_eq!(s.devices[&mac].quota_bytes, None, "zero clears the budget");
        assert!(set(&mut s, "abc").is_err(), "not a number");
        assert!(
            set(&mut s, "1.55").is_err(),
            "one decimal place is the limit"
        );
        assert!(set(&mut s, "-5").is_err(), "a negative budget is nonsense");
    }

    #[test]
    fn a_budget_alert_fires_once_a_day() {
        let mut s = state(&["192.168.10.200"]);
        let mac = real_mac(1);
        let now = 1_700_000_000;
        devices::learn_device(&mut s, mac, ip("192.168.10.50"), 100, now);
        devices::apply_edit(
            &mut s,
            mac,
            &devices::Edit {
                quota_gb: Some("1".into()),
                ..devices::Edit::default()
            },
        )
        .expect("a one gigabyte budget");
        // Over the line, but nothing has been flushed yet.
        s.devices.get_mut(&mac).expect("the device").day.up = 1_200_000_000;
        let mut hist = temp_history("budget");
        let mut tracker = history::Tracker::default();
        history::flush(&mut s, &mut hist, &mut tracker, now, 30).expect("a flush");
        let count = |s: &State| {
            s.alerts
                .iter()
                .filter(|a| a.kind == "quota_exceeded")
                .count()
        };
        assert_eq!(count(&s), 1, "the budget is mentioned once");
        assert!(
            !s.alerts.back().expect("an alert").muted,
            "a budget alert is worth sending to the operator"
        );
        // Twenty sweeps later, still once: the rule is per day, not per gigabyte.
        for step in 1..20 {
            s.devices.get_mut(&mac).expect("the device").day.up += 10_000_000;
            history::flush(&mut s, &mut hist, &mut tracker, now + step * 30, 30).expect("a flush");
        }
        assert_eq!(count(&s), 1, "once a day, not once per gigabyte");
    }

    #[test]
    fn a_quiet_device_is_still_recorded_but_not_sent() {
        let mut s = state(&["192.168.10.200"]);
        let mac = real_mac(1);
        let now = 1_700_000_000;
        devices::learn_device(&mut s, mac, ip("192.168.10.50"), 100, now);
        devices::apply_edit(
            &mut s,
            mac,
            &devices::Edit {
                notify: Some("quiet".into()),
                ..devices::Edit::default()
            },
        )
        .expect("a quiet rule");
        assert_eq!(s.devices[&mac].notify, devices::Notify::Quiet);
        // Fifteen minutes of silence: an alert, but only in the record.
        devices::sweep_devices(&mut s, now + 1_000);
        let offline = s.alerts.back().expect("an offline alert");
        assert_eq!(offline.kind, "device_offline", "the alert is still raised");
        assert!(offline.muted, "quiet means the phone stays quiet");
        // An alert that needs action is never silenced by a quiet rule.
        devices::learn_device(&mut s, real_mac(2), ip("192.168.10.50"), 100, now + 100);
        let conflicts: Vec<&alerts::Alert> = s
            .alerts
            .iter()
            .filter(|a| a.kind == "mac_conflict")
            .collect();
        assert_eq!(conflicts.len(), 2, "both holders are named");
        let quiet_one = conflicts
            .iter()
            .find(|a| a.mac.as_deref() == Some(&devices::mac_string(mac)))
            .expect("the quiet device");
        assert!(
            !quiet_one.muted,
            "a conflict is an alert, and a quiet device still gets to warn about one"
        );
    }

    #[test]
    fn never_means_nothing_leaves_the_box_but_everything_is_kept() {
        let mut s = state(&["192.168.10.200"]);
        let mac = real_mac(1);
        let now = 1_700_000_000;
        devices::learn_device(&mut s, mac, ip("192.168.10.50"), 100, now);
        devices::apply_edit(
            &mut s,
            mac,
            &devices::Edit {
                notify: Some("never".into()),
                ..devices::Edit::default()
            },
        )
        .expect("a never rule");
        devices::sweep_devices(&mut s, now + 1_000);
        let offline = s.alerts.back().expect("an offline alert");
        assert!(offline.muted, "never means never");
        // `never` is not `ignored`: the alert is in the record, and the device
        // still counts as being on the network.
        assert!(
            s.alerts.iter().any(|a| a.kind == "device_offline"),
            "the evidence is still collected"
        );
        assert!(s.devices.contains_key(&mac));
        assert_ne!(s.devices[&mac].trust, devices::Trust::Ignored);
    }

    #[test]
    fn online_seconds_accumulate_and_a_new_day_starts_over() {
        let mut s = state(&["192.168.10.200"]);
        let mac = real_mac(1);
        let day1 = 1_700_000_000;
        devices::learn_device(&mut s, mac, ip("192.168.10.50"), 100, day1);
        let mut hist = temp_history("uptime");
        let mut tracker = history::Tracker::default();
        history::flush(&mut s, &mut hist, &mut tracker, day1, 30).expect("a flush");
        history::flush(&mut s, &mut hist, &mut tracker, day1 + 60, 60).expect("a flush");
        assert!(
            s.devices[&mac].day.online_secs >= 90,
            "sweeps add up: {}",
            s.devices[&mac].day.online_secs
        );
        let today = history::day_of(day1);
        let stored = hist
            .today(&devices::mac_string(mac), today)
            .expect("a stored day");
        assert!(stored.online_secs >= 90, "and reach the database");
        assert!(stored.packets >= 1, "so does traffic");
        // The next UTC day starts from zero, and yesterday stays put.
        let tomorrow = day1 + history::DAY_SECS;
        history::flush(&mut s, &mut hist, &mut tracker, tomorrow, 30).expect("a flush");
        assert_eq!(s.devices[&mac].day.day, history::day_of(tomorrow));
        assert!(
            s.devices[&mac].day.online_secs <= 30,
            "a new day does not inherit yesterday's seconds"
        );
        let yesterday = hist
            .today(&devices::mac_string(mac), today)
            .expect("yesterday");
        assert!(yesterday.online_secs >= 90, "yesterday is still there");
    }

    #[test]
    fn history_accumulates_survives_and_prunes() {
        let mut hist = temp_history("prune");
        let now = 1_700_000_000;
        let today = history::day_of(now);
        let mac = "aa:bb:cc:dd:ee:ff";
        hist.add_day(
            mac,
            today,
            history::DayRow {
                up: 10,
                down: 20,
                packets: 3,
                online_secs: 60,
                sessions: 1,
            },
        )
        .expect("a first write");
        hist.add_day(
            mac,
            today,
            history::DayRow {
                up: 5,
                ..history::DayRow::default()
            },
        )
        .expect("a second write");
        let rows = hist.device_days(mac, 7, now).expect("a read");
        assert_eq!(rows.len(), 1, "one row per device per day");
        assert_eq!(rows[0].up, 15, "the deltas add up");
        assert_eq!(rows[0].down, 20);
        let net = hist.network_days(7, now).expect("a read");
        assert_eq!(net.len(), 1);
        assert_eq!(net[0].devices, 1, "one device contributed");
        assert_eq!(net[0].up + net[0].down, 35);
        let uptime = hist.uptime(7, now).expect("a read");
        assert_eq!(uptime.len(), 1);
        assert_eq!(uptime[0].1, 60, "sixty seconds online");
        assert_eq!(hist.sessions_recorded(mac), 0, "no sessions written yet");
        hist.add_session(mac, now - 100, now - 40)
            .expect("a session");
        hist.add_session(mac, now - 30, now - 30)
            .expect("a zero-length session is refused");
        assert_eq!(hist.sessions_recorded(mac), 1);
        // An old session, to prove retention reaches sessions as well as days.
        let old = now - 40 * history::DAY_SECS;
        hist.add_session(mac, old, old + 60)
            .expect("an old session");
        assert_eq!(hist.sessions_recorded(mac), 2);
        // Retention drops what is older than the window.
        hist.add_day(
            mac,
            today - 40,
            history::DayRow {
                up: 1,
                ..history::DayRow::default()
            },
        )
        .expect("an old day");
        assert_eq!(hist.device_days(mac, 400, now).expect("a read").len(), 2);
        let removed = hist.prune(now).expect("a prune");
        assert_eq!(removed, 2, "the old day and the old session are dropped");
        assert_eq!(hist.device_days(mac, 400, now).expect("a read").len(), 1);
    }

    #[test]
    fn a_session_is_written_when_a_device_goes_quiet_and_when_it_returns() {
        let mut s = state(&["192.168.10.200"]);
        let mac = real_mac(1);
        let t = 1_700_000_000;
        devices::learn_device(&mut s, mac, ip("192.168.10.50"), 100, t);
        let mut hist = temp_history("session");
        let mut tracker = history::Tracker::default();
        let text = devices::mac_string(mac);
        history::flush(&mut s, &mut hist, &mut tracker, t, 30).expect("a flush");
        // Silence long enough that the sweep retires it.
        devices::sweep_devices(&mut s, t + 400);
        history::flush(&mut s, &mut hist, &mut tracker, t + 400, 30).expect("a flush");
        assert_eq!(
            hist.sessions_recorded(&text),
            1,
            "going quiet closes a session"
        );
        // It comes back: a second session opens, and no third is invented.
        devices::learn_device(&mut s, mac, ip("192.168.10.50"), 100, t + 500);
        history::flush(&mut s, &mut hist, &mut tracker, t + 500, 30).expect("a flush");
        history::flush(&mut s, &mut hist, &mut tracker, t + 530, 30).expect("a flush");
        assert_eq!(
            hist.sessions_recorded(&text),
            1,
            "a flush is not a new session"
        );
        devices::sweep_devices(&mut s, t + 1_000);
        history::flush(&mut s, &mut hist, &mut tracker, t + 1_000, 30).expect("a flush");
        assert_eq!(
            hist.sessions_recorded(&text),
            2,
            "the second session is closed"
        );
    }

    #[test]
    fn a_day_number_reads_as_a_date_and_a_budget_as_gigabytes() {
        assert_eq!(
            api::date_text(history::day_of(1_700_000_000)),
            "2023-11-14",
            "unix 1700000000 is 2023-11-14 in UTC"
        );
        assert_eq!(api::gb_text(1_073_741_824), "1.0");
        assert_eq!(api::gb_text(1_181_116_006), "1.1");
        assert_eq!(api::gb_text(16_106_127_360), "15.0");
        // A device with no budget has no percentage, rather than a misleading 0%.
        let mut s = state(&["192.168.10.200"]);
        let mac = real_mac(1);
        devices::learn_device(&mut s, mac, ip("192.168.10.50"), 100, 1_700_000_000);
        let d = s.devices.get_mut(&mac).expect("a device");
        assert_eq!(api::quota_state(d), "none");
        assert_eq!(api::quota_pct(d), None);
        d.quota_bytes = Some(1000);
        d.day.up = 500;
        assert_eq!(api::quota_state(d), "under");
        assert_eq!(api::quota_pct(d), Some(50));
        d.day.up = 850;
        assert_eq!(api::quota_state(d), "near");
        d.day.up = 5000;
        assert_eq!(api::quota_state(d), "over");
        assert_eq!(
            api::quota_pct(d),
            Some(500),
            "over 100% is reported honestly"
        );
    }

    #[test]
    fn a_maker_suggests_a_kind_but_never_claims_to_know() {
        let mut s = state(&["192.168.10.200"]);
        // 3C:71:BF is Espressif, which is almost always a smart-home chip.
        devices::learn_device(
            &mut s,
            [0x3c, 0x71, 0xbf, 0x00, 0x00, 0x01],
            ip("192.168.10.30"),
            10,
            1_700_000_000,
        );
        let d = &s.devices[&[0x3c, 0x71, 0xbf, 0x00, 0x00, 0x01]];
        assert_eq!(d.kind, None, "nothing is decided without the operator");
        assert!(
            d.effective_kind().is_some(),
            "but a suggestion is available"
        );
        assert_eq!(d.effective_kind().map(Kind::as_str), Some("iot"));
    }

    #[test]
    fn a_mac_round_trips_and_junk_is_refused() {
        assert_eq!(
            devices::parse_mac("04:EA:56:00:00:01"),
            Some([0x04, 0xea, 0x56, 0x00, 0x00, 0x01])
        );
        assert_eq!(
            devices::parse_mac("04-EA-56-00-00-01"),
            Some([0x04, 0xea, 0x56, 0x00, 0x00, 0x01])
        );
        assert_eq!(
            devices::mac_string([0x04, 0xea, 0x56, 0x00, 0x00, 0x01]),
            "04:ea:56:00:00:01"
        );
        assert!(devices::parse_mac("not-a-mac").is_none());
        assert!(
            devices::parse_mac("1:2:3:4:5:6").is_some(),
            "single digits are still hex"
        );
        assert!(
            devices::parse_mac("04:ea:56:00:00").is_none(),
            "five octets is not an address"
        );
        assert!(
            devices::parse_mac("04:ea:56:00:00:zz").is_none(),
            "zz is not hex"
        );
    }

    #[test]
    fn peers_exclude_things_a_device_cannot_talk_to() {
        assert!(
            !devices::is_recordable_peer(&ip("224.0.0.251")),
            "a multicast group is not a peer"
        );
        assert!(
            !devices::is_recordable_peer(&ip("239.255.255.250")),
            "SSDP is not a peer"
        );
        assert!(
            !devices::is_recordable_peer(&ip("255.255.255.255")),
            "broadcast is not a peer"
        );
        assert!(
            !devices::is_recordable_peer(&ip("127.0.0.1")),
            "loopback is not a peer"
        );
        assert!(devices::is_recordable_peer(&ip("1.1.1.1")));
        assert!(devices::is_recordable_peer(&ip("192.168.10.5")));
    }

    //────────────────────────────────── names read from the wire

    #[test]
    fn a_dns_query_name_is_read_and_a_compressed_one_is_refused() {
        // A minimal query for "example.com".
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(&[7]);
        query.extend_from_slice(b"example");
        query.extend_from_slice(&[3]);
        query.extend_from_slice(b"com");
        query.extend_from_slice(&[0, 0, 1, 0, 1]);
        let summary = capture::dns_summary(&query).expect("a query parses");
        assert_eq!(summary.name, "example.com");
        assert!(summary.is_query);

        // A compression pointer where the name should be: refused, not guessed.
        let mut pointer = vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        pointer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        assert!(
            capture::dns_summary(&pointer).is_none(),
            "a pointer is not followed"
        );

        assert!(
            capture::dns_summary(&[0, 1, 2]).is_none(),
            "a stub is not a DNS message"
        );
        assert!(capture::dns_summary(&[]).is_none());
    }

    #[test]
    fn a_dns_answer_gives_the_address_behind_a_name() {
        // Response: question for "a.example", answer A 93.184.216.34.
        let mut packet = vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0];
        packet.extend_from_slice(&[1]);
        packet.extend_from_slice(b"a");
        packet.extend_from_slice(&[7]);
        packet.extend_from_slice(b"example");
        packet.extend_from_slice(&[0, 0, 1, 0, 1]);
        packet.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]);
        packet.extend_from_slice(&[0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        let summary = capture::dns_summary(&packet).expect("a response parses");
        assert!(!summary.is_query);
        assert_eq!(summary.name, "a.example");
        assert_eq!(summary.answer, Some(ip("93.184.216.34")));
    }

    #[test]
    fn an_mdns_name_becomes_a_suggested_name_but_never_an_override() {
        let mut s = state(&["192.168.10.200"]);
        let m = real_mac(7);
        devices::learn_device(&mut s, m, ip("192.168.10.40"), 10, 1_700_000_000);
        devices::note_domain(&mut s, ip("192.168.10.40"), "Living-Room-TV.local");
        assert_eq!(s.devices[&m].auto_name.as_deref(), Some("Living-Room-TV"));
        devices::apply_edit(
            &mut s,
            m,
            &devices::Edit {
                name: Some("Big TV".into()),
                ..devices::Edit::default()
            },
        )
        .expect("named");
        devices::note_domain(&mut s, ip("192.168.10.40"), "something-else.local");
        assert_eq!(
            s.devices[&m].display_name().as_deref(),
            Some("Big TV"),
            "the operator outranks the wire"
        );
        assert_eq!(
            s.devices[&m].auto_name.as_deref(),
            Some("Living-Room-TV"),
            "and is not overwritten"
        );
    }

    #[test]
    fn a_resolved_name_labels_the_flows_that_use_it() {
        let mut s = state(&["192.168.10.200"]);
        devices::note_resolved(&mut s, "cdn.example.com", ip("93.184.216.34"));
        assert_eq!(s.host_label(ip("93.184.216.34")), "cdn.example.com");
        assert_eq!(
            s.host_label(ip("1.2.3.4")),
            "1.2.3.4",
            "an unknown address stays an address"
        );
    }

    #[test]
    fn domain_lists_stay_bounded() {
        let mut s = state(&["192.168.10.200"]);
        let m = real_mac(8);
        devices::learn_device(&mut s, m, ip("192.168.10.41"), 10, 1_700_000_000);
        for i in 0..(state::MAX_DOMAINS_PER_DEVICE * 3) {
            devices::note_domain(&mut s, ip("192.168.10.41"), &format!("host{i}.example.com"));
        }
        assert_eq!(s.devices[&m].domains.len(), state::MAX_DOMAINS_PER_DEVICE);
    }

    //────────────────────────────────── history and graphs

    #[test]
    fn traffic_buckets_fill_gaps_and_stay_bounded() {
        let mut s = state(&["192.168.10.200"]);
        let m = real_mac(9);
        let base = 1_700_000_000;
        devices::learn_device(&mut s, m, ip("192.168.10.42"), 500, base);
        // Silence for a day, then traffic again: the graph must not grow an
        // unbounded number of empty minutes.
        devices::learn_device(&mut s, m, ip("192.168.10.42"), 900, base + 86_400);
        let d = &s.devices[&m];
        assert!(
            d.buckets.len() <= state::BUCKETS,
            "buckets are capped at an hour"
        );
        assert!(
            d.buckets.iter().any(|v| *v >= 900),
            "the recent traffic is in there"
        );
        let spark = d.sparkline(base + 86_400);
        assert_eq!(spark.len(), state::BUCKETS);
        assert!(
            spark.last().copied().unwrap_or(0) >= 900,
            "the newest minute is last"
        );
    }

    #[test]
    fn series_samples_rates_and_stays_bounded() {
        let mut s = state(&[]);
        let mut now = 1_700_000_000;
        for _ in 0..(state::SERIES_LEN * 2) {
            now += state::SERIES_STEP_SECS;
            s.packets += 50;
            s.bytes += 5_000;
            let (packets, bytes) = (s.packets, s.bytes);
            s.series.sample(packets, bytes, now);
        }
        assert_eq!(
            s.series.packets.len(),
            state::SERIES_LEN,
            "the graph window is bounded"
        );
        assert_eq!(s.series.packets_per_s, 10, "50 packets every 5 seconds");
        assert_eq!(s.series.bytes_per_s, 1_000);
    }

    //────────────────────────────────── api and http

    #[test]
    fn the_summary_carries_the_numbers_and_the_explanations() {
        let mut s = state(&["192.168.10.200"]);
        devices::learn_device(&mut s, real_mac(1), ip("192.168.10.50"), 100, 1_700_000_000);
        s.observe(
            "TCP",
            ep("192.168.10.50", 40000),
            ep("1.1.1.1", 443),
            100,
            1_700_000_000,
        );
        let json: serde_json::Value =
            serde_json::from_str(&api::summary_json(&s, 1_700_000_100)).expect("valid json");
        assert_eq!(json["devices"]["total"], 1);
        assert_eq!(
            json["devices"]["review"], 1,
            "an unreviewed device is in the queue count"
        );
        assert_eq!(json["health"]["state"], "ok");
        assert!(json["health"]["headline"].as_str().unwrap_or("").len() > 5);
        assert!(json["oui_prefixes"].as_u64().unwrap_or(0) > 10_000);
    }

    #[test]
    fn a_capture_failure_is_reported_as_the_worst_state() {
        let mut s = state(&["192.168.10.200"]);
        s.packets = 10;
        s.error = Some("permission denied: CAP_NET_RAW is not held".into());
        let json: serde_json::Value =
            serde_json::from_str(&api::summary_json(&s, 1_700_000_100)).expect("valid json");
        assert_eq!(json["health"]["state"], "bad");
        assert!(
            json["health"]["detail"]
                .as_str()
                .unwrap_or("")
                .contains("CAP_NET_RAW")
        );
    }

    #[test]
    fn the_device_endpoint_answers_with_history_and_hints() {
        let mut s = state(&["192.168.10.200"]);
        let m = [0x9a, 0x23, 0x0a, 0x5a, 0x5f, 0xe4];
        devices::learn_device(&mut s, m, ip("192.168.10.83"), 100, 1_700_000_000);
        devices::note_peer(
            &mut s,
            ip("192.168.10.83"),
            ip("93.184.216.34"),
            5_000,
            1_700_000_010,
        );
        let body = api::device_json(&s, "9a:23:0a:5a:5f:e4", 1_700_000_100, None).expect("found");
        let json: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        assert_eq!(json["randomized"], true);
        assert_eq!(json["kind_source"], "none");
        assert_eq!(json["peer_list"][0]["ip"], "93.184.216.34");
        assert!(json["ip_history"][0]["first_seen"].as_u64().unwrap_or(0) > 0);
        let hints = json["hints"].as_array().expect("hints");
        assert!(
            hints
                .iter()
                .any(|h| h.as_str().unwrap_or("").contains("randomised"))
        );
        assert!(
            api::device_json(&s, "aa:bb:cc:dd:ee:ff", 0, None).is_none(),
            "unknown device is a 404"
        );
        assert!(
            api::device_json(&s, "nonsense", 0, None).is_none(),
            "junk is a 404, not a panic"
        );
    }

    #[test]
    fn the_legacy_stats_endpoint_still_answers() {
        let mut s = state(&["192.168.10.200"]);
        s.observe(
            "TCP",
            ep("192.168.10.200", 5000),
            ep("1.1.1.1", 443),
            10,
            1_700_000_000,
        );
        let json: serde_json::Value =
            serde_json::from_str(&api::stats_json(&s, 1_700_000_100)).expect("valid json");
        for key in [
            "alerts",
            "alert_count",
            "devices",
            "device_count",
            "by_proto",
            "top_hosts",
            "top_flows",
            "uptime_s",
        ] {
            assert!(
                !json[key].is_null(),
                "the documented key {key} must still be there"
            );
        }
    }

    #[test]
    fn the_glossary_parses_and_every_entry_can_explain_itself() {
        let json: serde_json::Value = serde_json::from_str(http::GLOSSARY).expect("valid json");
        let terms = json.as_array().expect("an array of terms");
        assert!(
            terms.len() >= 25,
            "a glossary this dashboard needs is not three entries"
        );
        for term in terms {
            let name = term["term"].as_str().unwrap_or("");
            let body = term["body"].as_str().unwrap_or("");
            assert!(!name.is_empty(), "every entry is named");
            assert!(body.len() > 40, "{name} needs a real explanation");
            assert!(
                term.get("short")
                    .and_then(|s| s.as_str())
                    .is_some_and(|s| !s.is_empty()),
                "{name} needs a one-line version for the tooltips"
            );
        }
    }

    #[test]
    fn the_dashboard_is_self_contained() {
        assert!(http::DASHBOARD.contains("<!doctype html"));
        assert!(
            !http::DASHBOARD.contains("http://") && !http::DASHBOARD.contains("https://"),
            "the page must not reach out to a CDN"
        );
        assert!(!http::SCRIPT.contains("http://") && !http::SCRIPT.contains("https://"));
        assert!(!http::STYLE.contains("http://") && !http::STYLE.contains("https://"));
        assert!(
            http::DASHBOARD.contains("glossary"),
            "the page links to the glossary"
        );
        assert!(
            http::SCRIPT.contains("/api/devices"),
            "the page reads the device API"
        );
        assert!(
            http::SCRIPT.contains("method"),
            "the page can write an edit"
        );
    }

    #[test]
    fn queries_are_parsed_and_decoded() {
        let q = http::Query::parse("/api/flows?limit=25&q=two%20words&proto=TCP");
        assert_eq!(q.get("limit"), Some("25".into()));
        assert_eq!(
            q.get("q"),
            Some("two words".into()),
            "percent escapes are decoded"
        );
        assert_eq!(q.get("proto"), Some("TCP".into()));
        assert_eq!(q.get("missing"), None);
        assert_eq!(q.get_usize("limit"), Some(25));
        assert_eq!(q.get_usize("q"), None, "a non-number is not a number");
        assert_eq!(http::Query::parse("/api/devices").get("limit"), None);
        assert_eq!(http::Query::of(&[("a", "b")]).get("a"), Some("b".into()));
    }

    #[test]
    fn csv_output_is_quoted_where_it_has_to_be() {
        assert_eq!(api::csv_field("plain"), "plain");
        assert_eq!(api::csv_field("has,comma"), "\"has,comma\"");
        assert_eq!(api::csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(api::csv_field("two\nlines"), "\"two\nlines\"");
    }

    #[test]
    fn exports_come_back_with_a_filename_and_the_right_type() {
        let mut s = state(&["192.168.10.200"]);
        devices::learn_device(&mut s, real_mac(1), ip("192.168.10.50"), 100, 1_700_000_000);
        let (ctype, name, body) =
            api::export(&s, &http::Query::of(&[("what", "devices")]), 1_700_000_100);
        assert_eq!(ctype, "text/csv; charset=utf-8");
        assert!(
            has_extension(&name, "csv"),
            "the export names its format: {name}"
        );
        assert!(body.starts_with("mac,"), "a CSV starts with its header row");
        assert!(body.contains("04:ea:56:00:00:01"));
        let (_, json_name, json_body) = api::export(
            &s,
            &http::Query::of(&[("what", "devices"), ("format", "json")]),
            0,
        );
        assert!(
            has_extension(&json_name, "json"),
            "the export names its format: {json_name}"
        );
        serde_json::from_str::<serde_json::Value>(&json_body).expect("valid json export");
        let (_, alerts_name, _) = api::export(&s, &http::Query::of(&[("what", "alerts")]), 0);
        assert!(alerts_name.contains("alerts"));
    }

    #[test]
    fn alerts_can_be_filtered_by_kind_and_severity() {
        let mut s = state(&[]);
        alerts::emit_alert(&mut s, "new_device", "alert", "aa", "one");
        alerts::emit_alert(&mut s, "device_offline", "notable", "bb", "two");
        let json: serde_json::Value = serde_json::from_str(&api::alerts_json(
            &s,
            &http::Query::of(&[("kind", "device_offline")]),
        ))
        .expect("valid json");
        assert_eq!(json["alerts"].as_array().expect("array").len(), 1);
        assert_eq!(json["alerts"][0]["kind"], "device_offline");
        assert_eq!(json["counts"]["alert"], 1);
        assert_eq!(json["counts"]["notable"], 1);
        let all: serde_json::Value =
            serde_json::from_str(&api::alerts_json(&s, &http::Query::of(&[]))).expect("json");
        assert_eq!(all["alerts"].as_array().expect("array").len(), 2);
        let kinds = all["kinds"].as_array().expect("kinds");
        assert!(
            kinds.len() >= 9,
            "the dashboard lists every kind with its explanation"
        );
    }

    #[test]
    fn flows_can_be_searched_by_name_service_or_address() {
        let mut s = state(&["192.168.10.200"]);
        devices::learn_device(&mut s, real_mac(1), ip("192.168.10.50"), 100, 1_700_000_000);
        s.observe(
            "TCP",
            ep("192.168.10.50", 40000),
            ep("93.184.216.34", 443),
            100,
            1_700_000_000,
        );
        devices::note_resolved(&mut s, "cdn.example.com", ip("93.184.216.34"));
        let hit: serde_json::Value =
            serde_json::from_str(&api::flows_json(&s, &http::Query::of(&[("q", "example")])))
                .expect("json");
        assert_eq!(hit["flows"].as_array().expect("array").len(), 1);
        assert_eq!(hit["flows"][0]["service"], "https");
        assert_eq!(hit["flows"][0]["remote"], true);
        let miss: serde_json::Value = serde_json::from_str(&api::flows_json(
            &s,
            &http::Query::of(&[("q", "nothing-here")]),
        ))
        .expect("json");
        assert!(miss["flows"].as_array().expect("array").is_empty());
        let by_mac = api::flows_json(&s, &http::Query::of(&[("mac", "04:ea:56:00:00:01")]));
        let by_mac: serde_json::Value = serde_json::from_str(&by_mac).expect("json");
        assert_eq!(by_mac["flows"].as_array().expect("array").len(), 1);
    }

    #[test]
    fn impossible_lengths_and_unknown_ports_do_not_break_anything() {
        assert!(state::plausible_len(1500));
        assert!(!state::plausible_len(200_000));
        assert_eq!(devices::port_label(443), "https");
        assert_eq!(devices::port_label(5353), "mdns (local discovery)");
        assert_eq!(
            devices::port_label(64_999),
            "",
            "an unknown port is simply unknown"
        );
    }

    #[test]
    fn humanised_numbers_read_the_way_a_person_writes_them() {
        assert_eq!(devices::humanise_bytes(999), "999 B");
        assert_eq!(devices::humanise_bytes(1024), "1.0 KB");
        assert_eq!(devices::humanise_bytes(1024 * 1024 * 3 / 2), "1.5 MB");
        assert_eq!(devices::humanise_secs(45), "45s");
        assert_eq!(devices::humanise_secs(300), "5m 0s");
        assert_eq!(devices::humanise_secs(3661), "1h 1m");
        assert_eq!(devices::humanise_secs(90_000), "1d 1h");
    }

    #[test]
    fn arguments_are_parsed_or_refused() {
        let ok = parse_args(&[
            "--iface".into(),
            "eth0".into(),
            "--port".into(),
            "9000".into(),
            "--devices".into(),
            "/tmp/d.json".into(),
            "--demo".into(),
        ])
        .expect("valid arguments")
        .expect("a config, not early return");
        assert_eq!(ok.iface.as_deref(), Some("eth0"));
        assert_eq!(ok.port, Some(9000));
        assert!(ok.demo);
        assert!(
            ok.dns_names,
            "reading DNS names is on unless it is turned off"
        );
        assert!(
            !parse_args(&["--no-dns-names".into()])
                .expect("ok")
                .expect("config")
                .dns_names
        );
        assert!(
            parse_args(&["--nonsense".into()]).is_err(),
            "a typo must be an error"
        );
        assert!(
            parse_args(&["--help".into()])
                .expect("help is fine")
                .is_none(),
            "--help returns"
        );
        assert!(
            parse_args(&["--version".into()])
                .expect("version is fine")
                .is_none()
        );
    }

    #[test]
    fn a_device_row_carries_what_the_table_shows() {
        let mut s = state(&["192.168.10.200"]);
        let m = real_mac(1);
        devices::learn_device(&mut s, m, ip("192.168.10.50"), 100, 1_700_000_000);
        let row = api::device_row(&s.devices[&m], &s, 1_700_000_100);
        for key in [
            "mac",
            "display_name",
            "vendor",
            "randomized",
            "trust",
            "ip",
            "online",
            "bytes",
            "spark",
            "hints",
            "kind_source",
            "trust_note",
        ] {
            assert!(
                !row[key].is_null() || key == "display_name",
                "{key} must be present in a device row"
            );
        }
        assert_eq!(row["vendor"], "Intel Corporate");
        assert_eq!(row["randomized"], false);
        assert_eq!(row["bytes_human"], "100 B");
    }
}
