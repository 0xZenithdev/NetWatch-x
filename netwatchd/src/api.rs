//! The JSON the dashboard reads.
//!
//! Two rules shape every function here. First, nothing is invented: a value is
//! either measured, or explicitly absent (`null`), and the UI is built to show
//! absence honestly. Second, every payload that could be misread carries the
//! plain-language explanation of what it means, so the answer to "what is this
//! number?" travels with the number.

use std::net::IpAddr;

use crate::devices::{
    Device, Kind, Trust, humanise_bytes, humanise_secs, is_lan_address, port_label,
    possible_duplicate,
};
use crate::http::Query;
use crate::state::{State, now_unix};
use crate::{alerts, oui};

/// How much of a list an API call may ask for.
const MAX_LIMIT: usize = 500;
const DEFAULT_FLOWS: usize = 60;

fn limit(q: &Query, default: usize) -> usize {
    q.get_usize("limit").unwrap_or(default).clamp(1, MAX_LIMIT)
}

/// The one-line answer to "is this thing working?".
fn health(s: &State) -> serde_json::Value {
    if let Some(err) = &s.error {
        return serde_json::json!({
            "state": "bad",
            "headline": "Capture is not running",
            "detail": err,
            "action": "Scroll to the banner below: it names the exact command that fixes this."
        });
    }
    if s.mode == crate::state::Mode::Demo {
        return serde_json::json!({
            "state": "demo",
            "headline": "Demo mode — the traffic shown is made up",
            "detail": "Nothing is being captured. Start netwatchd without --demo, with CAP_NET_RAW, for real data.",
            "action": "See packaging/netwatchd.service for the unit that grants the capability."
        });
    }
    if s.kernel_dropped > 0 {
        return serde_json::json!({
            "state": "warn",
            "headline": "Capturing, but the kernel is dropping packets",
            "detail": format!(
                "{} packets dropped out of {} delivered by the kernel. Counts stay correct, but the picture has holes.",
                s.kernel_dropped, s.kernel_received
            ),
            "action": "Usually the box is simply too busy. Nothing is broken."
        });
    }
    if s.packets == 0 {
        return serde_json::json!({
            "state": "warn",
            "headline": "Capturing, but nothing has arrived yet",
            "detail": "The capability is in place — the interface has simply carried no traffic since the daemon started.",
            "action": "If this persists on a busy network, check that the interface is the one carrying the LAN."
        });
    }
    serde_json::json!({
        "state": "ok",
        "headline": "Capturing normally",
        "detail": format!("Reading frames from {} with no dropped packets.", s.iface),
        "action": ""
    })
}

/// Counts the dashboard shows as chips, computed once rather than per card.
fn device_counts(s: &State) -> serde_json::Value {
    let all: Vec<&Device> = s.devices.values().collect();
    let count = |f: &dyn Fn(&&Device) -> bool| all.iter().filter(|d| f(d)).count();
    let by_trust = |t: Trust| all.iter().filter(|d| d.trust == t).count();
    serde_json::json!({
        "total": all.len(),
        "online": count(&|d| d.online),
        "offline": count(&|d| !d.online),
        "randomized": count(&|d| d.is_randomized()),
        "named": count(&|d| d.name.is_some()),
        "review": count(&|d| d.needs_review()),
        "unknown_trust": by_trust(Trust::Unknown),
        "known": by_trust(Trust::Known),
        "trusted": by_trust(Trust::Trusted),
        "ignored": by_trust(Trust::Ignored),
        "vendors_known": count(&|d| d.vendor.is_some()),
    })
}

pub fn alert_counts(s: &State) -> serde_json::Value {
    let mut alert = 0;
    let mut notable = 0;
    let mut info = 0;
    for a in &s.alerts {
        match a.severity {
            "alert" => alert += 1,
            "notable" => notable += 1,
            _ => info += 1,
        }
    }
    serde_json::json!({
        "total": s.alerts.len(),
        "alert": alert,
        "notable": notable,
        "info": info,
    })
}

/// `GET /api/summary` — everything the header and the overview tab need, in one
/// small request. The dashboard polls this; the heavier lists are asked for only
/// when their tab is open.
pub fn summary_json(s: &State, now: u64) -> String {
    let mut proto: Vec<(&str, u64)> = Vec::new();
    for (key, flow) in &s.flows {
        match proto.iter_mut().find(|(name, _)| *name == key.proto) {
            Some((_, total)) => *total += flow.bytes(),
            None => proto.push((key.proto, flow.bytes())),
        }
    }
    proto.sort_by_key(|(_, bytes)| std::cmp::Reverse(*bytes));

    let mut ports: Vec<(u16, u64)> = Vec::new();
    for key in s.flows.keys() {
        for end in [key.a, key.b] {
            if end.port == 0 {
                continue;
            }
            match ports.iter_mut().find(|(port, _)| *port == end.port) {
                Some((_, total)) => *total += 1,
                None => ports.push((end.port, 1)),
            }
        }
    }
    ports.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    let top_ports: Vec<serde_json::Value> = ports
        .iter()
        .take(8)
        .map(|(port, count)| {
            serde_json::json!({ "port": port, "flows": count, "label": port_label(*port) })
        })
        .collect();

    let tops = top_devices(s, now, 5);
    serde_json::json!({
        "ok": true,
        "generated_at": now,
        "started_at": s.started_at,
        "uptime_s": s.uptime_secs(),
        "uptime_human": humanise_secs(s.uptime_secs()),
        "iface": s.iface,
        "mode": s.mode.as_str(),
        "health": health(s),
        "error": s.error,
        "note": s.note,
        "packets": s.packets,
        "bytes": s.bytes,
        "bytes_human": humanise_bytes(s.bytes),
        "flows": s.flows.len(),
        "kernel_received": s.kernel_received,
        "kernel_dropped": s.kernel_dropped,
        "packets_per_s": s.series.packets_per_s,
        "bytes_per_s": s.series.bytes_per_s,
        "devices": device_counts(s),
        "alerts": alert_counts(s),
        "by_proto": proto.iter().map(|(name, bytes)| serde_json::json!({ "proto": name, "bytes": bytes })).collect::<Vec<_>>(),
        "top_ports": top_ports,
        "top_devices": tops,
        "series": {
            "step_s": crate::state::SERIES_STEP_SECS,
            "t": s.series.t.iter().copied().collect::<Vec<_>>(),
            "packets": s.series.packets.iter().copied().collect::<Vec<_>>(),
            "bytes": s.series.bytes.iter().copied().collect::<Vec<_>>(),
        },
        "oui_prefixes": oui::table_size(),
    })
    .to_string()
}

fn top_devices(s: &State, now: u64, take: usize) -> Vec<serde_json::Value> {
    let mut devices: Vec<&Device> = s.devices.values().collect();
    devices.sort_by_key(|d| std::cmp::Reverse(d.bytes));
    devices
        .iter()
        .take(take)
        .map(|d| {
            serde_json::json!({
                "mac": crate::devices::mac_string(d.mac),
                "name": d.display_name(),
                "ip": d.primary_ip().map(|ip| ip.to_string()),
                "bytes": d.bytes,
                "bytes_human": humanise_bytes(d.bytes),
                "online": d.online,
                "spark": d.sparkline(now),
            })
        })
        .collect()
}

/// The list view of one device. Everything the table needs, and nothing the
/// detail page alone needs.
/// Today's total for a device, both directions.
fn today_total(d: &Device) -> u64 {
    d.day.up.saturating_add(d.day.down)
}

/// How far through today's budget a device is, as a percentage.
///
/// Integer arithmetic, and capped: a device that has moved a terabyte against a
/// one-gigabyte budget should read "over budget", not "899999%".
pub fn quota_pct(d: &Device) -> Option<u64> {
    let quota = d.quota_bytes?;
    if quota == 0 {
        return None;
    }
    Some((today_total(d).saturating_mul(100) / quota).min(999))
}

/// `over`, `near` (past four fifths) or `under`.
pub fn quota_state(d: &Device) -> &'static str {
    match quota_pct(d) {
        None => "none",
        Some(pct) if pct >= 100 => "over",
        Some(pct) if pct >= 80 => "near",
        Some(_) => "under",
    }
}

/// Gigabytes as the operator typed them, to one decimal place, without floats.
pub fn gb_text(bytes: u64) -> String {
    const TENTH: u64 = 107_374_182; // a tenth of a GiB
    let tenths = bytes / TENTH;
    format!("{}.{}", tenths / 10, tenths % 10)
}

/// A UTC day number as `2026-10-08`.
///
/// Howard Hinnant's civil-from-days: a dozen lines of integer arithmetic that
/// mean this binary needs no calendar library.
pub fn date_text(day: u64) -> String {
    let z = i64::try_from(day).unwrap_or(0) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

pub fn device_row(d: &Device, s: &State, now: u64) -> serde_json::Value {
    let peers_remote = d.peers.keys().filter(|ip| !is_lan_address(ip)).count();
    let mut ports: Vec<u16> = d.ports.keys().copied().collect();
    ports.sort_unstable();
    let mut domains: Vec<(&String, &u64)> = d.domains.iter().collect();
    domains.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
    serde_json::json!({
        "mac": crate::devices::mac_string(d.mac),
        "name": d.name,
        "auto_name": d.auto_name,
        "display_name": d.display_name(),
        "vendor": d.vendor,
        "randomized": d.is_randomized(),
        "kind": d.kind.map(Kind::as_str),
        "kind_guess": d.kind_guess.map(Kind::as_str),
        "kind_guess_label": d.kind_guess.map(Kind::label),
        "kind_source": if d.kind.is_some() { "you" } else if d.kind_guess.is_some() { "guess" } else { "none" },
        "trust": d.trust.as_str(),
        "trust_note": d.trust.explain(),
        "notes": d.notes,
        // What the operator set for this device, and where today stands against
        // it. All of it integer arithmetic, so the page and the alert agree.
        "notify": d.notify.as_str(),
        "notify_label": d.notify.label(),
        "quota_bytes": d.quota_bytes,
        "quota_text": d.quota_bytes.map(gb_text),
        "today_up": d.day.up,
        "today_down": d.day.down,
        "today_bytes": today_total(d),
        "today_human": humanise_bytes(today_total(d)),
        "quota_pct": quota_pct(d),
        "quota_state": quota_state(d),
        "ip": d.primary_ip().map(|ip| ip.to_string()),
        "ips": d.ips.iter().map(|r| r.ip.to_string()).collect::<Vec<_>>(),
        "first_seen": d.first_seen,
        "last_seen": d.last_seen,
        "online": d.online,
        "offline_for_s": d.offline_since.map(|since| now.saturating_sub(since)),
        "packets": d.packets,
        "bytes": d.bytes,
        "bytes_human": humanise_bytes(d.bytes),
        "up_bytes": d.up_bytes,
        "down_bytes": d.down_bytes,
        "sessions": d.sessions,
        "peers": d.peers.len(),
        "remote_peers": peers_remote,
        "ports": ports,
        "domains": domains.iter().take(5).map(|(name, _)| (*name).clone()).collect::<Vec<_>>(),
        "spark": d.sparkline(now),
        "hints": hints(d, s, now),
    })
}

/// Plain-language observations about a device, so the dashboard can explain
/// itself without the reader having to know what a MAC address is.
fn hints(d: &Device, s: &State, now: u64) -> Vec<String> {
    let mut out = Vec::new();
    if d.is_randomized() {
        out.push("Its hardware address is randomised. Phones and laptops do this on purpose, so the same device can look new every day and cannot be identified by its maker.".to_string());
    } else if let Some(vendor) = d.vendor_name() {
        out.push(format!("The first half of its address is registered to {vendor}, so that is who made the network chip."));
    } else {
        out.push(
            "Its maker is not in the registry we carry, which is normal for small manufacturers."
                .to_string(),
        );
    }
    if d.kind.is_none()
        && let Some(guess) = d.kind_guess
    {
        out.push(format!("\"{}\" is a guess based on the maker, not something observed. You can set it properly.", guess.label()));
    }
    if d.ips.len() > 1 {
        out.push(format!("It has been seen using {} different addresses, which usually means DHCP gave it a new one.", d.ips.len()));
    }
    if d.needs_review() {
        out.push("Nobody has said what this is yet. It is in the review queue.".to_string());
    }
    if !d.online
        && let Some(since) = d.offline_since
    {
        out.push(format!(
            "Nothing heard from it for {}.",
            humanise_secs(now.saturating_sub(since))
        ));
    }
    if let Some(other) = possible_duplicate(
        s,
        d.mac,
        d.primary_ip()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        d.first_seen,
    ) {
        out.push(format!("{} used the same address at a different time, and was never online at the same moment — quite possibly this same device before it changed its address.", crate::devices::mac_string(other)));
    }
    out
}

/// `GET /api/devices`
pub fn devices_json(s: &State, now: u64) -> String {
    let mut devices: Vec<&Device> = s.devices.values().collect();
    // Online first, then whoever was heard from most recently: the order a
    // person would ask for.
    devices.sort_by_key(|d| (std::cmp::Reverse(d.online), std::cmp::Reverse(d.last_seen)));
    let rows: Vec<serde_json::Value> = devices.iter().map(|d| device_row(d, s, now)).collect();
    let kinds: Vec<serde_json::Value> = Kind::all()
        .iter()
        .map(|k| serde_json::json!({ "value": k.as_str(), "label": k.label() }))
        .collect();
    let trusts: Vec<serde_json::Value> =
        [Trust::Unknown, Trust::Known, Trust::Trusted, Trust::Ignored]
            .iter()
            .map(|t| serde_json::json!({ "value": t.as_str(), "note": t.explain() }))
            .collect();
    serde_json::json!({
        "ok": true,
        "generated_at": now,
        "counts": device_counts(s),
        "kinds": kinds,
        "trusts": trusts,
        "review_queue": crate::devices::review_queue(s)
            .iter()
            .map(|m| crate::devices::mac_string(*m))
            .collect::<Vec<_>>(),
        "over_budget": s
            .devices
            .values()
            .filter(|d| d.quota_bytes.is_some_and(|q| today_total(d) >= q))
            .map(|d| crate::devices::mac_string(d.mac))
            .collect::<Vec<_>>(),
        "devices": rows,
    })
    .to_string()
}

/// `GET /api/devices/<mac>` — one device in full.
pub fn device_json(
    s: &State,
    mac_text: &str,
    now: u64,
    history: Option<&crate::history::History>,
) -> Option<String> {
    let mac = crate::devices::parse_mac(mac_text)?;
    let d = s.devices.get(&mac)?;
    let mut peers: Vec<(&IpAddr, &crate::devices::Peer)> = d.peers.iter().collect();
    peers.sort_by_key(|(_, p)| std::cmp::Reverse(p.bytes));
    let mut ports: Vec<(&u16, &u64)> = d.ports.iter().collect();
    ports.sort_by_key(|(_, bytes)| std::cmp::Reverse(**bytes));
    let mut domains: Vec<(&String, &u64)> = d.domains.iter().collect();
    domains.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
    let device_alerts: Vec<serde_json::Value> = s
        .alerts
        .iter()
        .rev()
        .filter(|a| a.mac.as_deref() == Some(&crate::devices::mac_string(mac)))
        .take(20)
        .map(alerts::Alert::to_json)
        .collect();
    let mut timeline: Vec<serde_json::Value> = d
        .timeline
        .iter()
        .rev()
        .map(|x| serde_json::json!({ "start": x.start, "end": x.end }))
        .collect();
    if d.online {
        timeline.insert(
            0,
            serde_json::json!({ "start": d.session_start, "end": now, "ongoing": true }),
        );
    }

    let mut row = device_row(d, s, now);
    if let Some(object) = row.as_object_mut() {
        object.insert("ok".into(), serde_json::Value::Bool(true));
        for (key, value) in related_lists(s, d, &peers, &ports, &domains) {
            object.insert(key.into(), value);
        }
        object.insert("timeline".into(), serde_json::json!(timeline));
        object.insert("alert_history".into(), serde_json::json!(device_alerts));
        object.insert(
            "duplicate_of".into(),
            match d.primary_ip().and_then(|ip| possible_duplicate(s, d.mac, ip, d.first_seen)) {
                Some(other) => serde_json::json!({
                    "mac": crate::devices::mac_string(other),
                    "name": s.devices.get(&other).and_then(Device::display_name),
                    "reason": "Same address, never online at the same time — likely the same physical device before it changed its address.",
                }),
                None => serde_json::Value::Null,
            },
        );
        if let Some(hist) = history {
            object.insert("history".into(), device_history(hist, mac, 30, now));
        }
    }
    Some(row.to_string())
}

/// One device's retained days, and the uptime they add up to.
fn device_history(
    hist: &crate::history::History,
    mac: [u8; 6],
    days: u64,
    now: u64,
) -> serde_json::Value {
    let text = crate::devices::mac_string(mac);
    let rows = hist.device_days(&text, days, now).unwrap_or_default();
    let online: u64 = rows.iter().map(|r| r.online_secs).sum();
    let seen_days = u64::try_from(rows.len()).unwrap_or(0);
    let window = seen_days.saturating_mul(crate::history::DAY_SECS);
    serde_json::json!({
        "window_days": days,
        "seen_days": seen_days,
        "online_secs": online,
        "online_human": crate::devices::humanise_secs(online),
        "uptime_pct": online.saturating_mul(100).checked_div(window).unwrap_or(0).min(100),
        "sessions_recorded": hist.sessions_recorded(&text),
        "days": rows
            .iter()
            .map(|r| serde_json::json!({
                "day": r.day,
                "date": date_text(r.day),
                "up": r.up,
                "down": r.down,
                "total": r.up.saturating_add(r.down),
                "total_human": humanise_bytes(r.up.saturating_add(r.down)),
                "packets": r.packets,
                "online_secs": r.online_secs,
                "online_human": crate::devices::humanise_secs(r.online_secs),
                "sessions": r.sessions,
            }))
            .collect::<Vec<_>>(),
    })
}

/// `GET /api/history` — what was kept: the network day by day, and who has been
/// up. This is the answer to "was it like this last week?", which the live view
/// cannot give because it only knows about now.
pub fn history_json(s: &State, hist: &crate::history::History, days: u64, now: u64) -> String {
    let net = hist.network_days(days, now).unwrap_or_default();
    let uptime = hist.uptime(days, now).unwrap_or_default();
    let size = s
        .history_path
        .as_deref()
        .map_or(0, crate::history::History::size_bytes);
    let leaderboard: Vec<serde_json::Value> = uptime
        .iter()
        .map(|(mac, online, seen_days)| {
            let name = crate::devices::parse_mac(mac)
                .and_then(|m| s.devices.get(&m))
                .and_then(Device::display_name);
            let window = seen_days.saturating_mul(crate::history::DAY_SECS);
            serde_json::json!({
                "mac": mac,
                "name": name,
                "online_secs": online,
                "online_human": crate::devices::humanise_secs(*online),
                "days_seen": seen_days,
                "uptime_pct": online.saturating_mul(100).checked_div(window).unwrap_or(0).min(100),
            })
        })
        .collect();
    serde_json::json!({
        "ok": true,
        "generated_at": now,
        "window_days": days,
        "keep_days": hist.keep_days(),
        "file_bytes": size,
        "file_human": humanise_bytes(size),
        "network": net
            .iter()
            .map(|d| serde_json::json!({
                "day": d.day,
                "date": date_text(d.day),
                "up": d.up,
                "down": d.down,
                "total": d.up.saturating_add(d.down),
                "total_human": humanise_bytes(d.up.saturating_add(d.down)),
                "devices": d.devices,
            }))
            .collect::<Vec<_>>(),
        "uptime": leaderboard,
    })
    .to_string()
}

/// The lists that hang off one device: the addresses it has used, who it talks
/// to, which ports, and which names it asked for.
fn related_lists(
    s: &State,
    d: &crate::devices::Device,
    peers: &[(&IpAddr, &crate::devices::Peer)],
    ports: &[(&u16, &u64)],
    domains: &[(&String, &u64)],
) -> Vec<(&'static str, serde_json::Value)> {
    let ip_history: Vec<serde_json::Value> = d
        .ips
        .iter()
        .map(|r| {
            serde_json::json!({
                "ip": r.ip.to_string(),
                "first_seen": r.first_seen,
                "last_seen": r.last_seen,
                "local": is_lan_address(&r.ip),
            })
        })
        .collect();
    let peer_list: Vec<serde_json::Value> = peers
        .iter()
        .take(40)
        .map(|(ip, p)| {
            serde_json::json!({
                "ip": ip.to_string(),
                "name": s.host_label(**ip),
                "bytes": p.bytes,
                "bytes_human": humanise_bytes(p.bytes),
                "packets": p.packets,
                "first_seen": p.first_seen,
                "last_seen": p.last_seen,
                "local": is_lan_address(ip),
            })
        })
        .collect();
    let port_list: Vec<serde_json::Value> = ports
        .iter()
        .take(24)
        .map(|(port, bytes)| {
            serde_json::json!({
                "port": port,
                "label": port_label(**port),
                "bytes": bytes,
                "bytes_human": humanise_bytes(**bytes),
            })
        })
        .collect();
    let domain_list: Vec<serde_json::Value> = domains
        .iter()
        .take(40)
        .map(|(name, count)| serde_json::json!({ "name": name, "count": count }))
        .collect();
    vec![
        ("ip_history", serde_json::json!(ip_history)),
        ("peer_list", serde_json::json!(peer_list)),
        ("port_list", serde_json::json!(port_list)),
        ("domain_list", serde_json::json!(domain_list)),
    ]
}

/// `GET /api/alerts`
pub fn alerts_json(s: &State, q: &Query) -> String {
    let want_severity = q.get("severity");
    let want_kind = q.get("kind");
    let want_mac = q.get("mac");
    let rows: Vec<serde_json::Value> = s
        .alerts
        .iter()
        .rev()
        .filter(|a| want_severity.is_none() || want_severity.as_deref() == Some(a.severity))
        .filter(|a| want_kind.is_none() || want_kind.as_deref() == Some(a.kind))
        .filter(|a| want_mac.is_none() || want_mac.as_deref() == a.mac.as_deref())
        .take(limit(q, 100))
        .map(alerts::Alert::to_json)
        .collect();
    let kinds: Vec<serde_json::Value> = [
        "new_device",
        "device_offline",
        "device_back_online",
        "address_change",
        "mac_conflict",
        "new_peer",
        "traffic_spike",
        "quota_exceeded",
        "capture_failed",
        "test",
    ]
    .iter()
    .map(|kind| serde_json::json!({ "kind": kind, "why": alerts::explain(kind) }))
    .collect();
    serde_json::json!({
        "ok": true,
        "generated_at": now_unix(),
        "counts": alert_counts(s),
        "kinds": kinds,
        "alerts": rows,
    })
    .to_string()
}

/// `GET /api/flows`
pub fn flows_json(s: &State, q: &Query) -> String {
    let rows = flow_rows(s, q);
    serde_json::json!({
        "ok": true,
        "generated_at": now_unix(),
        "returned": rows.len(),
        "total_flows": s.flows.len(),
        "flows": rows,
    })
    .to_string()
}

fn flow_rows(s: &State, q: &Query) -> Vec<serde_json::Value> {
    let query = q.get("q").unwrap_or_default().to_lowercase();
    let proto = q.get("proto");
    let mac = q.get("mac").and_then(|m| crate::devices::parse_mac(&m));

    let mut flows: Vec<(&crate::state::FlowKey, &crate::state::Flow)> = s.flows.iter().collect();
    flows.sort_by_key(|(_, f)| std::cmp::Reverse(f.bytes()));
    flows
        .iter()
        .filter(|(k, _)| proto.as_deref().is_none_or(|want| want == k.proto))
        .filter_map(|(k, f)| {
            let (local, peer, up, down) = s.orient(k, f);
            let local_ip = local.map(|e| e.ip);
            let owner = local_ip.and_then(|ip| s.device_by_ip(ip));
            if let Some(want) = mac
                && owner != Some(want)
            {
                return None;
            }
            let label = s.host_label(peer.ip);
            let service = port_label(peer.port);
            let owner_name = owner
                .and_then(|m| s.devices.get(&m))
                .and_then(Device::display_name);
            if !query.is_empty() {
                let haystack = format!(
                    "{} {} {} {} {}",
                    peer.ip,
                    label,
                    service,
                    owner.map_or(String::new(), crate::devices::mac_string),
                    owner_name.clone().unwrap_or_default()
                )
                .to_lowercase();
                if !haystack.contains(&query) {
                    return None;
                }
            }
            Some(serde_json::json!({
                "proto": k.proto,
                "a": k.a.to_string(),
                "b": k.b.to_string(),
                "local": local.map(|e| e.to_string()),
                "peer": peer.to_string(),
                "peer_ip": peer.ip.to_string(),
                "peer_name": label,
                "peer_port": peer.port,
                "service": service,
                "remote": !is_lan_address(&peer.ip),
                "owner_mac": owner.map(crate::devices::mac_string),
                "owner_name": owner_name,
                "up_bytes": up,
                "down_bytes": down,
                "packets": f.packets(),
                "bytes": f.bytes(),
                "bytes_human": humanise_bytes(f.bytes()),
                "first_seen": f.first_seen,
                "last_seen": f.last_seen,
            }))
        })
        .take(limit(q, DEFAULT_FLOWS))
        .collect()
}

/// `GET /api/stats` — kept as the documented endpoint, now a superset of what it
/// used to return. The dashboard uses the smaller calls, but anything already
/// pointed at this keeps working.
pub fn stats_json(s: &State, now: u64) -> String {
    let mut by_proto = serde_json::Map::new();
    for (key, flow) in &s.flows {
        let entry = by_proto
            .entry(key.proto.to_string())
            .or_insert_with(|| serde_json::Value::from(0));
        let current = entry.as_u64().unwrap_or(0);
        *entry = serde_json::Value::from(current + flow.bytes());
    }

    let flows: Vec<serde_json::Value> = flow_rows(s, &Query::of(&[("limit", "60")]));

    let alerts: Vec<serde_json::Value> = s
        .alerts
        .iter()
        .rev()
        .take(50)
        .map(alerts::Alert::to_json)
        .collect();

    let mut devices: Vec<&Device> = s.devices.values().collect();
    devices.sort_by_key(|d| std::cmp::Reverse(d.last_seen));
    let devices: Vec<serde_json::Value> = devices.iter().map(|d| device_row(d, s, now)).collect();

    let mut hosts = serde_json::Map::new();
    for (key, flow) in &s.flows {
        let (local, peer, _, _) = s.orient(key, flow);
        if local.is_none() {
            continue;
        }
        let entry = hosts
            .entry(peer.ip.to_string())
            .or_insert_with(|| serde_json::Value::from(0));
        let current = entry.as_u64().unwrap_or(0);
        *entry = serde_json::Value::from(current + flow.bytes());
    }
    let mut host_list: Vec<(String, u64)> = hosts
        .into_iter()
        .map(|(host, bytes)| (host, bytes.as_u64().unwrap_or(0)))
        .collect();
    host_list.sort_by_key(|(_, bytes)| std::cmp::Reverse(*bytes));
    let top_hosts: Vec<serde_json::Value> = host_list
        .iter()
        .take(20)
        .map(|(host, bytes)| {
            let label = host
                .parse::<IpAddr>()
                .map_or_else(|_| host.clone(), |ip| s.host_label(ip));
            serde_json::json!({
                "host": host,
                "bytes": bytes,
                "bytes_human": humanise_bytes(*bytes),
                "name": label,
            })
        })
        .collect();

    serde_json::json!({
        "ok": true,
        "alerts": alerts,
        "alert_count": s.alerts.len(),
        "alert_counts": alert_counts(s),
        "devices": devices,
        "device_count": s.devices.len(),
        "device_counts": device_counts(s),
        "iface": s.iface,
        "mode": s.mode.as_str(),
        "started_at": s.started_at,
        "uptime_s": s.uptime_secs(),
        "packets": s.packets,
        "bytes": s.bytes,
        "flows": s.flows.len(),
        "kernel_received": s.kernel_received,
        "kernel_dropped": s.kernel_dropped,
        "error": s.error,
        "note": s.note,
        "by_proto": serde_json::Value::Object(by_proto),
        "top_hosts": top_hosts,
        "top_flows": flows,
        "health": health(s),
    })
    .to_string()
}

//────────────────────────────────────────────────────────── glossary

/// `GET /api/glossary` — the terms used anywhere in the dashboard, in plain
/// language. Served from the same embedded file the UI is built from, so the
/// two cannot drift apart.
pub fn glossary_json() -> String {
    let terms: serde_json::Value =
        serde_json::from_str(crate::http::GLOSSARY).unwrap_or_else(|_| serde_json::json!([]));
    serde_json::json!({ "ok": true, "terms": terms }).to_string()
}

//────────────────────────────────────────────────────────── exports

/// Quote a CSV field when it contains anything that would break the row.
///
/// Public so the quoting rule itself is testable, since a subtly wrong escape is
/// the kind of bug that silently corrupts an export.
#[must_use]
pub fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn csv_row(values: &[String]) -> String {
    values
        .iter()
        .map(|v| csv_field(v))
        .collect::<Vec<_>>()
        .join(",")
        + "\n"
}

/// `GET /api/export?what=devices|flows|alerts&format=csv|json`
///
/// A monitor the operator cannot get data out of is a monitor they cannot
/// argue with, so the raw material is always exportable.
pub fn export(s: &State, q: &Query, now: u64) -> (String, String, String) {
    let what = q.get("what").unwrap_or_else(|| "devices".into());
    let format = q.get("format").unwrap_or_else(|| "csv".into());
    let (name, body) = match (what.as_str(), format.as_str()) {
        ("flows", "json") => (
            "netwatch-flows.json".to_string(),
            flows_json(s, &Query::of(&[("limit", "500")])),
        ),
        ("flows", _) => ("netwatch-flows.csv".to_string(), flows_csv(s)),
        ("alerts", "json") => (
            "netwatch-alerts.json".to_string(),
            alerts_json(s, &Query::of(&[("limit", "500")])),
        ),
        ("alerts", _) => ("netwatch-alerts.csv".to_string(), alerts_csv(s)),
        ("devices", "json") => ("netwatch-devices.json".to_string(), devices_json(s, now)),
        _ => ("netwatch-devices.csv".to_string(), devices_csv(s)),
    };
    let ctype = if format == "json" {
        "application/json".to_string()
    } else {
        "text/csv; charset=utf-8".to_string()
    };
    (ctype, name, body)
}

pub fn devices_csv(s: &State) -> String {
    let mut out = csv_row(&[
        "mac".into(),
        "name".into(),
        "suggested_name".into(),
        "vendor".into(),
        "kind".into(),
        "trust".into(),
        "randomized".into(),
        "online".into(),
        "addresses".into(),
        "first_seen".into(),
        "last_seen".into(),
        "packets".into(),
        "bytes".into(),
        "up_bytes".into(),
        "down_bytes".into(),
        "peers".into(),
        "notes".into(),
    ]);
    let mut devices: Vec<&Device> = s.devices.values().collect();
    devices.sort_by_key(|d| std::cmp::Reverse(d.last_seen));
    for d in devices {
        out.push_str(&csv_row(&[
            crate::devices::mac_string(d.mac),
            d.name.clone().unwrap_or_default(),
            d.auto_name.clone().unwrap_or_default(),
            d.vendor.clone().unwrap_or_default(),
            d.effective_kind()
                .map_or(String::new(), |k| k.as_str().to_string()),
            d.trust.as_str().to_string(),
            d.is_randomized().to_string(),
            d.online.to_string(),
            d.ips
                .iter()
                .map(|r| r.ip.to_string())
                .collect::<Vec<_>>()
                .join(" "),
            d.first_seen.to_string(),
            d.last_seen.to_string(),
            d.packets.to_string(),
            d.bytes.to_string(),
            d.up_bytes.to_string(),
            d.down_bytes.to_string(),
            d.peers.len().to_string(),
            d.notes.clone(),
        ]));
    }
    out
}

fn flows_csv(s: &State) -> String {
    let mut out = csv_row(&[
        "proto".into(),
        "device_mac".into(),
        "device_name".into(),
        "peer".into(),
        "peer_name".into(),
        "service".into(),
        "up_bytes".into(),
        "down_bytes".into(),
        "packets".into(),
        "first_seen".into(),
        "last_seen".into(),
    ]);
    let mut flows: Vec<(&crate::state::FlowKey, &crate::state::Flow)> = s.flows.iter().collect();
    flows.sort_by_key(|(_, f)| std::cmp::Reverse(f.bytes()));
    for (key, flow) in flows.iter().take(MAX_LIMIT) {
        let (local, peer, up, down) = s.orient(key, flow);
        let owner = local.map(|e| e.ip).and_then(|ip| s.device_by_ip(ip));
        out.push_str(&csv_row(&[
            key.proto.to_string(),
            owner.map_or(String::new(), crate::devices::mac_string),
            owner
                .and_then(|m| s.devices.get(&m))
                .and_then(Device::display_name)
                .unwrap_or_default(),
            peer.to_string(),
            s.host_label(peer.ip),
            port_label(peer.port).to_string(),
            up.to_string(),
            down.to_string(),
            flow.packets().to_string(),
            flow.first_seen.to_string(),
            flow.last_seen.to_string(),
        ]));
    }
    out
}

fn alerts_csv(s: &State) -> String {
    let mut out = csv_row(&[
        "ts".into(),
        "severity".into(),
        "kind".into(),
        "subject".into(),
        "name".into(),
        "address".into(),
        "detail".into(),
        "why".into(),
    ]);
    for a in s.alerts.iter().rev().take(MAX_LIMIT) {
        out.push_str(&csv_row(&[
            a.ts.to_string(),
            a.severity.to_string(),
            a.kind.to_string(),
            a.subject.clone(),
            a.name.clone().unwrap_or_default(),
            a.address.clone().unwrap_or_default(),
            a.detail.clone(),
            alerts::explain(a.kind).to_string(),
        ]));
    }
    out
}
