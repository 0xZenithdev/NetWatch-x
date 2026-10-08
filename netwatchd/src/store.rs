//! Remembering the inventory across restarts.
//!
//! Without this every restart re-announces the whole network as new devices —
//! an alert storm on exactly the occasion (a crash, an upgrade) when the
//! operator is least willing to be shouted at. Loaded devices count as already
//! known, start offline, and come back online silently on their next frame.

use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::path::Path;

use crate::devices::{
    DayCounters, Device, IpRecord, Kind, Notify, Peer, Session, Trust, parse_mac,
};
use crate::state::State;

/// Anything below this is not a real timestamp. Older builds wrote seconds
/// since the process started, so their numbers are meaningless after a restart
/// and are dropped rather than shown as a date in 1970.
const PLAUSIBLE_EPOCH: u64 = 1_000_000_000;

/// Peers and ports kept on disk. The full sets stay in memory; the file is a
/// summary, because a device list that grows with every conversation it ever had
/// would end up larger than the log.
const SAVED_PEERS: usize = 24;
const SAVED_PORTS: usize = 16;
const SAVED_DOMAINS: usize = 16;
const SAVED_SESSIONS: usize = 12;

fn stamp(value: u64) -> u64 {
    if value >= PLAUSIBLE_EPOCH { value } else { 0 }
}

/// Write the inventory where a restart can find it, atomically so a crash
/// mid-write cannot leave a half-file behind.
pub fn save_devices(path: &Path, s: &State) -> std::io::Result<()> {
    let mut devices: Vec<&Device> = s.devices.values().collect();
    devices.sort_by_key(|d| d.first_seen);

    let rows: Vec<serde_json::Value> = devices.iter().map(|d| device_row(d)).collect();
    let body = serde_json::json!({
        "version": 2,
        "saved_at": crate::state::now_unix(),
        "devices": rows,
    });
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec(&body).unwrap_or_default())?;
    std::fs::rename(&tmp, path)
}

fn device_row(d: &Device) -> serde_json::Value {
    let ips: Vec<serde_json::Value> = d
        .ips
        .iter()
        .map(|r| serde_json::json!({ "ip": r.ip.to_string(), "first_seen": stamp(r.first_seen), "last_seen": stamp(r.last_seen) }))
        .collect();
    let mut peers: Vec<(&IpAddr, &Peer)> = d.peers.iter().collect();
    peers.sort_by_key(|(_, p)| std::cmp::Reverse(p.bytes));
    let peers: Vec<serde_json::Value> = peers
        .iter()
        .take(SAVED_PEERS)
        .map(|(ip, p)| {
            serde_json::json!({
                "ip": ip.to_string(),
                "bytes": p.bytes,
                "packets": p.packets,
                "last_seen": stamp(p.last_seen),
            })
        })
        .collect();
    let mut ports: Vec<(&u16, &u64)> = d.ports.iter().collect();
    ports.sort_by_key(|(_, bytes)| std::cmp::Reverse(**bytes));
    let ports: Vec<serde_json::Value> = ports
        .iter()
        .take(SAVED_PORTS)
        .map(|(port, bytes)| serde_json::json!({ "port": port, "bytes": bytes }))
        .collect();
    let mut domains: Vec<(&String, &u64)> = d.domains.iter().collect();
    domains.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
    let domains: Vec<serde_json::Value> = domains
        .iter()
        .take(SAVED_DOMAINS)
        .map(|(name, count)| serde_json::json!({ "name": name, "count": count }))
        .collect();
    let sessions: Vec<&Session> = d.timeline.iter().rev().take(SAVED_SESSIONS).collect();
    let sessions: Vec<serde_json::Value> = sessions
        .iter()
        .map(|x| serde_json::json!({ "start": stamp(x.start), "end": stamp(x.end) }))
        .collect();
    let buckets: Vec<u64> = d.buckets.iter().copied().collect();

    serde_json::json!({
        "mac": crate::devices::mac_string(d.mac),
        "ips": ips,
        "first_seen": stamp(d.first_seen),
        "last_seen": stamp(d.last_seen),
        "packets": d.packets,
        "bytes": d.bytes,
        "up_bytes": d.up_bytes,
        "down_bytes": d.down_bytes,
        "sessions": d.sessions,
        "last_offline_alert": stamp(d.last_offline_alert),
        "name": d.name,
        "auto_name": d.auto_name,
        "vendor": d.vendor,
        "kind": d.kind.map(Kind::as_str),
        "trust": d.trust.as_str(),
        "notes": d.notes,
        // The operator's own settings, kept beside the inventory rather than in
        // the history database: this is intent, and the database is measurement.
        "quota_bytes": d.quota_bytes,
        "notify": d.notify.as_str(),
        "peers": peers,
        "ports": ports,
        "domains": domains,
        "timeline": sessions,
        "buckets": buckets,
        "bucket_minute": d.bucket_at,
    })
}

/// Load a previously written inventory, returning how many devices were usable.
///
/// Never fatal: a damaged file must not stop the monitor, so a row that will not
/// parse is skipped and the rest are kept.
pub fn load_devices(path: &Path, s: &mut State) -> usize {
    let Ok(text) = std::fs::read_to_string(path) else {
        return 0;
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) else {
        return 0;
    };
    // Version 2 is an object; version 1 was a bare array of rows.
    let rows = match &parsed {
        serde_json::Value::Array(rows) => rows.clone(),
        serde_json::Value::Object(map) => match map.get("devices").and_then(|v| v.as_array()) {
            Some(rows) => rows.clone(),
            None => return 0,
        },
        _ => return 0,
    };
    let mut loaded = 0;
    for row in rows {
        if let Some(device) = device_from_row(&row) {
            s.devices.insert(device.mac, device);
            loaded += 1;
        }
    }
    loaded
}

fn device_from_row(row: &serde_json::Value) -> Option<Device> {
    let mac = parse_mac(row.get("mac")?.as_str()?)?;
    let ips = ips_from_row(row);
    let num = |key: &str| {
        row.get(key)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    };
    let text = |key: &str| {
        row.get(key)
            .and_then(|v| v.as_str())
            .map(ToString::to_string)
    };
    let first_seen = stamp(num("first_seen"));
    let last_seen = stamp(num("last_seen"));
    let buckets: VecDeque<u64> = row.get("buckets").and_then(|v| v.as_array()).map_or_else(
        || VecDeque::from(vec![0]),
        |a| a.iter().filter_map(serde_json::Value::as_u64).collect(),
    );
    let bucket_at = num("bucket_minute");
    Some(Device {
        mac,
        ips,
        first_seen,
        last_seen,
        packets: num("packets"),
        bytes: num("bytes"),
        up_bytes: num("up_bytes"),
        down_bytes: num("down_bytes"),
        online: false,
        offline_since: None,
        sessions: num("sessions"),
        session_start: last_seen,
        last_offline_alert: stamp(num("last_offline_alert")),
        last_conflict_alert: 0,
        last_spike_alert: 0,
        name: text("name"),
        auto_name: text("auto_name"),
        vendor: text("vendor"),
        kind: text("kind").as_deref().and_then(Kind::parse),
        kind_guess: None,
        trust: text("trust")
            .as_deref()
            .and_then(Trust::parse)
            .unwrap_or(Trust::Unknown),
        notes: text("notes").unwrap_or_default(),
        quota_bytes: row.get("quota_bytes").and_then(serde_json::Value::as_u64),
        notify: text("notify")
            .as_deref()
            .and_then(Notify::parse)
            .unwrap_or_default(),
        // Filled in from the history database at startup, so a restart continues
        // today's totals rather than starting them over.
        day: DayCounters::default(),
        flushed: DayCounters::default(),
        quota_alerted_day: 0,
        peers: peers_from_row(row),
        ports: ports_from_row(row),
        domains: domains_from_row(row),
        buckets,
        bucket_at,
        timeline: timeline_from_row(row),
    })
}

/// Addresses, accepting both shapes: version 2 objects and version 1 strings.
fn ips_from_row(row: &serde_json::Value) -> Vec<IpRecord> {
    let Some(items) = row.get("ips").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in items {
        match item {
            serde_json::Value::String(text) => {
                if let Ok(ip) = text.parse() {
                    out.push(IpRecord {
                        ip,
                        first_seen: 0,
                        last_seen: 0,
                    });
                }
            }
            serde_json::Value::Object(_) => {
                let ip = item
                    .get("ip")
                    .and_then(|v| v.as_str())
                    .and_then(|t| t.parse().ok());
                if let Some(ip) = ip {
                    out.push(IpRecord {
                        ip,
                        first_seen: stamp(
                            item.get("first_seen")
                                .and_then(serde_json::Value::as_u64)
                                .unwrap_or(0),
                        ),
                        last_seen: stamp(
                            item.get("last_seen")
                                .and_then(serde_json::Value::as_u64)
                                .unwrap_or(0),
                        ),
                    });
                }
            }
            _ => {}
        }
    }
    out
}

fn peers_from_row(row: &serde_json::Value) -> BTreeMap<IpAddr, Peer> {
    let mut out = BTreeMap::new();
    for item in row
        .get("peers")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let Some(ip) = item
            .get("ip")
            .and_then(|v| v.as_str())
            .and_then(|t| t.parse().ok())
        else {
            continue;
        };
        out.insert(
            ip,
            Peer {
                bytes: item
                    .get("bytes")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0),
                packets: item
                    .get("packets")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0),
                first_seen: stamp(
                    item.get("first_seen")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0),
                ),
                last_seen: stamp(
                    item.get("last_seen")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0),
                ),
            },
        );
    }
    out
}

fn ports_from_row(row: &serde_json::Value) -> BTreeMap<u16, u64> {
    let mut out = BTreeMap::new();
    for item in row
        .get("ports")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let Some(port) = item.get("port").and_then(serde_json::Value::as_u64) else {
            continue;
        };
        let Ok(port) = u16::try_from(port) else {
            continue;
        };
        out.insert(
            port,
            item.get("bytes")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        );
    }
    out
}

fn domains_from_row(row: &serde_json::Value) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for item in row
        .get("domains")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let (Some(name), Some(count)) = (
            item.get("name").and_then(|v| v.as_str()),
            item.get("count").and_then(serde_json::Value::as_u64),
        ) else {
            continue;
        };
        out.insert(name.to_string(), count);
    }
    out
}

fn timeline_from_row(row: &serde_json::Value) -> VecDeque<Session> {
    let mut out = VecDeque::new();
    for item in row
        .get("timeline")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let start = stamp(
            item.get("start")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        );
        let end = stamp(
            item.get("end")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        );
        if start > 0 || end > 0 {
            out.push_back(Session { start, end });
        }
    }
    out
}
