//! Shared state: what the capture threads write and the HTTP threads read.
//!
//! Everything here is wall-clock time. Earlier versions counted seconds since
//! the process started, which meant an upgrade silently rewrote history — a
//! device last seen "before the restart" reappeared as seen four million
//! seconds ago, and the dashboard could not say when anything happened.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::alerts::Alert;
use crate::devices::Device;

//────────────────────────────────────────────────────────────── tuning
//
// Every threshold lives here with its reason, because the numbers are the
// behaviour: a reader who wants to know why a device went quiet at 4 minutes
// rather than 5 should not have to grep for a magic constant.

/// How long a device may be silent before the dashboard calls it offline. Short,
/// because this only changes what is displayed.
pub const VISUAL_IDLE_SECS: u64 = 300;
/// Silence after which going offline is worth an alert. Fifteen minutes: long
/// enough that a phone sleeping its Wi-Fi does not generate one, short enough
/// that a device that is really gone is still news.
pub const OFFLINE_ALERT_SECS: u64 = 900;
/// After alerting about one device, stay quiet about it for this long. Without
/// a re-arm window a device that is on for ten minutes and off for ten all day
/// produces an alert every twenty minutes, which is how an alert channel gets
/// muted and stops being a security control.
pub const OFFLINE_REARM_SECS: u64 = 21_600;
/// Addresses kept per device: a host that keeps changing address must not grow
/// its record without limit.
pub const MAX_IPS_PER_DEVICE: usize = 8;
pub const MAX_PEERS_PER_DEVICE: usize = 48;
pub const MAX_PORTS_PER_DEVICE: usize = 32;
pub const MAX_DOMAINS_PER_DEVICE: usize = 48;
/// Hard ceiling on remembered devices, oldest-and-anonymous evicted first.
pub const MAX_DEVICES: usize = 1024;
/// Hard ceiling on the flow table. Unbounded flow state is what made this
/// daemon grow to over a gigabyte of RSS over days.
pub const MAX_FLOWS: usize = 20_000;
/// Per-minute traffic buckets kept per device (one hour).
pub const BUCKETS: usize = 60;
/// Dashboard throughput samples, one per [`SERIES_STEP_SECS`].
pub const SERIES_LEN: usize = 72;
pub const SERIES_STEP_SECS: u64 = 5;
/// How many distinct addresses are remembered for domain-name resolution.
pub const MAX_HOSTNAMES: usize = 2048;
/// A domain name longer than this is not a name, it is a parsing bug.
pub const MAX_NAME_LEN: usize = 100;

#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Whether capture is real or fabricated.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Live,
    Demo,
}

impl Mode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Live => "live",
            Mode::Demo => "demo",
        }
    }
}

//────────────────────────────────────────────────────────────── flows

/// One end of a conversation. Ordered so the two ends can be put in a canonical
/// order, which is what makes aggregation bidirectional: the reply updates the
/// same entry as the request instead of inventing a second flow.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct FlowKey {
    pub proto: &'static str,
    /// The lower of the two endpoints. Never the "source": a key that depended
    /// on who spoke first would split every conversation in two.
    pub a: Endpoint,
    pub b: Endpoint,
}

#[derive(Default, Clone)]
pub struct Flow {
    pub ab_packets: u64,
    pub ab_bytes: u64,
    pub ba_packets: u64,
    pub ba_bytes: u64,
    pub first_seen: u64,
    pub last_seen: u64,
}

impl Flow {
    #[must_use]
    pub fn packets(&self) -> u64 {
        self.ab_packets + self.ba_packets
    }
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.ab_bytes + self.ba_bytes
    }
}

//────────────────────────────────────────────────────────────── series

/// Rolling throughput samples, so the dashboard can draw a graph without
/// keeping any history of its own.
#[derive(Default)]
pub struct Series {
    pub t: VecDeque<u64>,
    pub packets: VecDeque<u64>,
    pub bytes: VecDeque<u64>,
    last_packets: u64,
    last_bytes: u64,
    last_at: u64,
    pub packets_per_s: u64,
    pub bytes_per_s: u64,
}

impl Series {
    /// Fold the running totals into a sample, at most once every
    /// [`SERIES_STEP_SECS`]. Called from the sweep, so no extra thread.
    pub fn sample(&mut self, total_packets: u64, total_bytes: u64, now: u64) {
        if self.last_at == 0 {
            self.last_at = now;
            self.last_packets = total_packets;
            self.last_bytes = total_bytes;
            return;
        }
        let elapsed = now.saturating_sub(self.last_at);
        if elapsed < SERIES_STEP_SECS {
            return;
        }
        let dp = total_packets.saturating_sub(self.last_packets);
        let db = total_bytes.saturating_sub(self.last_bytes);
        self.packets_per_s = dp / elapsed;
        self.bytes_per_s = db / elapsed;
        push_bounded(&mut self.t, now, SERIES_LEN);
        push_bounded(&mut self.packets, dp, SERIES_LEN);
        push_bounded(&mut self.bytes, db, SERIES_LEN);
        self.last_at = now;
        self.last_packets = total_packets;
        self.last_bytes = total_bytes;
    }
}

fn push_bounded(q: &mut VecDeque<u64>, value: u64, cap: usize) {
    q.push_back(value);
    while q.len() > cap {
        q.pop_front();
    }
}

//────────────────────────────────────────────────────────────── state

pub struct State {
    pub iface: String,
    pub mode: Mode,
    pub started_at: u64,
    /// Process start, used only for an uptime readout.
    pub started: Instant,
    pub flows: HashMap<FlowKey, Flow>,
    pub packets: u64,
    pub bytes: u64,
    pub kernel_dropped: u32,
    pub kernel_received: u32,
    pub error: Option<String>,
    pub note: Option<String>,
    /// Addresses of the interface being captured, used to tell "up" from "down".
    pub local_ips: Vec<IpAddr>,
    /// Most recent alerts, oldest first.
    pub alerts: VecDeque<Alert>,
    /// Where alerts are appended, if anywhere.
    pub alert_sink: Option<PathBuf>,
    /// Where the device inventory is remembered, if anywhere.
    pub device_store: Option<PathBuf>,
    /// The history database, when retention is on.
    ///
    /// Shared rather than owned by the keeper so a page can read a year of
    /// uptime while the keeper writes this minute's row. Both hold it for
    /// milliseconds, and the keeper is the only writer.
    pub history: Option<Arc<Mutex<crate::history::History>>>,
    /// Where the history database lives, for reporting its size.
    pub history_path: Option<PathBuf>,
    /// Hosts seen on the wire, keyed by MAC.
    pub devices: HashMap<[u8; 6], Device>,
    /// Which hardware address was last seen using an address, and when. Used to
    /// notice one address being used by two devices.
    pub ip_owners: HashMap<IpAddr, ([u8; 6], u64)>,
    /// Domain names asked for, mapped to the addresses they resolved to.
    pub hostnames: HashMap<IpAddr, String>,
    pub series: Series,
    /// Set when the sweep has unsaved inventory changes, so the disk is written
    /// once in a while rather than on every packet.
    pub dirty: bool,
    /// Whether DNS names may be read from the wire at all.
    pub read_dns_names: bool,
}

impl State {
    #[must_use]
    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    /// Fold one packet into the conversation it belongs to.
    ///
    /// The endpoints are ordered before they become the key, so a request and
    /// its reply share an entry and the direction is recorded in the counters
    /// rather than by creating a second row.
    pub fn observe(
        &mut self,
        proto: &'static str,
        src: Endpoint,
        dst: Endpoint,
        len: u64,
        now: u64,
    ) {
        let forward = (src.ip, src.port) <= (dst.ip, dst.port);
        let (a, b) = if forward { (src, dst) } else { (dst, src) };
        let entry = self
            .flows
            .entry(FlowKey { proto, a, b })
            .or_insert_with(|| Flow {
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
        self.packets += 1;
        self.bytes += len;
    }

    /// Which end of a conversation belongs to this network, who the peer is, and
    /// how much went each way.
    ///
    /// Three cases, in order. One end being one of *our* addresses is the
    /// obvious one. If neither is, the conversation may still belong to a device
    /// on this network — this box sits in the gateway position, so most traffic
    /// it sees is someone else's — and then that device is the end the
    /// direction is stated relative to. Only when neither end is ours or a
    /// known device does this claim nothing at all: traffic between two
    /// strangers has no "up".
    #[must_use]
    pub fn orient(&self, k: &FlowKey, f: &Flow) -> (Option<Endpoint>, Endpoint, u64, u64) {
        if self.local_ips.contains(&k.a.ip) {
            return (Some(k.a), k.b, f.ab_bytes, f.ba_bytes);
        }
        if self.local_ips.contains(&k.b.ip) {
            return (Some(k.b), k.a, f.ba_bytes, f.ab_bytes);
        }
        let a_is_device = self.device_by_ip(k.a.ip).is_some();
        let b_is_device = self.device_by_ip(k.b.ip).is_some();
        match (a_is_device, b_is_device) {
            // Ours first, then a device on this network — and when two devices
            // are talking to each other the direction is real but relative to
            // the lower address, not to this network. Stable, and the dashboard
            // says "on this network" rather than implying egress.
            (true, _) => (Some(k.a), k.b, f.ab_bytes, f.ba_bytes),
            (false, true) => (Some(k.b), k.a, f.ba_bytes, f.ab_bytes),
            (false, false) => (None, k.b, 0, 0),
        }
    }

    /// Find the device using an address, newest sighting first.
    ///
    /// The index built while learning answers this in one lookup for the common
    /// case; the scan is the fallback for an address only ever seen on the
    /// receiving side.
    #[must_use]
    pub fn device_by_ip(&self, ip: IpAddr) -> Option<[u8; 6]> {
        if let Some((mac, _)) = self.ip_owners.get(&ip)
            && self.devices.contains_key(mac)
        {
            return Some(*mac);
        }
        self.devices
            .values()
            .filter(|d| d.ips.iter().any(|r| r.ip == ip))
            .max_by_key(|d| d.last_seen)
            .map(|d| d.mac)
    }

    /// A label for a remote address: the name it resolved to, else the address.
    #[must_use]
    pub fn host_label(&self, ip: IpAddr) -> String {
        self.hostnames
            .get(&ip)
            .cloned()
            .unwrap_or_else(|| ip.to_string())
    }

    /// Bound the flow table.
    ///
    /// Measured on a real LAN: the flow map grew without limit and the daemon
    /// reached 1.2 GB of RSS within days. Dropping the least recently active
    /// quarter keeps the table honest — a conversation that has not carried a
    /// packet in hours is history, not state.
    pub fn trim_flows(&mut self) {
        if self.flows.len() <= MAX_FLOWS {
            return;
        }
        let mut seen: Vec<u64> = self.flows.values().map(|f| f.last_seen).collect();
        seen.sort_unstable();
        let cutoff = seen[seen.len() / 4];
        self.flows.retain(|_, f| f.last_seen > cutoff);
    }

    /// Bound the hostname map, oldest-inserted first out.
    pub fn trim_hostnames(&mut self) {
        if self.hostnames.len() <= MAX_HOSTNAMES {
            return;
        }
        let overflow = self.hostnames.len() - MAX_HOSTNAMES;
        let doomed: Vec<IpAddr> = self.hostnames.keys().take(overflow).copied().collect();
        for ip in doomed {
            self.hostnames.remove(&ip);
        }
    }
}

/// Whether a packet length is within what a captured frame can be, to keep a
/// nonsense value from a decoder out of the byte counters.
#[must_use]
pub fn plausible_len(len: usize) -> bool {
    len <= 65_535
}
