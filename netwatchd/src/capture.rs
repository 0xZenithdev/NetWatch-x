//! Capture: reading frames, folding them into flows, and learning from them.
//!
//! Everything here is read-only. `CAP_NET_RAW` is needed to observe; nothing is
//! ever transmitted or modified, and no packet is ever composed.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use etherparse::{LinkSlice, NetSlice, SlicedPacket, TransportSlice};

use crate::devices::{
    learn_device, note_direction, note_domain, note_peer, note_port, note_resolved,
};
use crate::state::{Endpoint, Mode, State, now_unix, plausible_len};

/// Headers only: enough to read addresses and ports, not enough to retain
/// content. Never raise this without deciding what the extra bytes mean.
pub const SNAPLEN: i32 = 128;

/// DNS and mDNS both speak the same wire format on the wire.
const PORT_DNS: u16 = 53;
const PORT_MDNS: u16 = 5353;

fn friendly(msg: &str) -> String {
    let lower = msg.to_lowercase();
    if lower.contains("permission") || lower.contains("not permitted") {
        format!(
            "{msg}\n\nThis is the CAP_NET_RAW check. Grant it to this binary once:\n  \
             sudo setcap cap_net_raw,cap_net_admin=eip {}\n\n\
             Better: run it from the systemd unit in packaging/, which carries\n\
             AmbientCapabilities so a rebuild cannot silently strip it.",
            std::env::current_exe().map_or_else(
                |_| "<path to netwatchd>".into(),
                |p| p.display().to_string(),
            )
        )
    } else {
        msg.to_string()
    }
}

pub fn set_error(state: &Arc<Mutex<State>>, msg: &str) {
    if let Ok(mut s) = state.lock() {
        s.error = Some(msg.to_string());
        // A monitor that has silently stopped monitoring is the worst failure
        // mode there is, so losing capture raises an alert and not just a note
        // on a dashboard nobody is looking at.
        crate::alerts::emit_alert(&mut s, "capture_failed", "alert", "capture stopped", msg);
    }
}

pub fn capture_loop(iface: &str, state: &Arc<Mutex<State>>) {
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
            // BOTH empty-poll outcomes need a sleep. In NON-BLOCKING mode libpcap reports an empty
            // buffer as TimeoutExpired (0) -- NoMorePackets (-2) is what a savefile returns, so on a
            // live non-blocking capture this arm is the one that gets hit, and an empty arm spins the
            // thread flat out. Measured 6 Oct 2026: 8d22h of CPU time on one thread while the
            // interface carried 81 packets/second, i.e. a full core burnt on an idle LAN. A 5 ms
            // pause costs ~1% of a core and still drains 81 pps with no backlog.
            Err(pcap::Error::TimeoutExpired) => std::thread::sleep(Duration::from_millis(5)),
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

/// One captured frame, decoded just far enough to know who, where and how much.
fn ingest(data: &[u8], state: &Arc<Mutex<State>>) {
    if !plausible_len(data.len()) {
        return;
    }
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
    let (proto, sport, dport, payload) = match &pkt.transport {
        Some(TransportSlice::Tcp(t)) => ("TCP", t.source_port(), t.destination_port(), t.payload()),
        Some(TransportSlice::Udp(u)) => ("UDP", u.source_port(), u.destination_port(), u.payload()),
        _ => ("other", 0, 0, &[][..]),
    };
    // The Ethernet header identifies which host sent this; that is the whole
    // basis of device discovery here.
    let macs = match &pkt.link {
        Some(LinkSlice::Ethernet2(eth)) => Some((eth.source(), eth.destination())),
        _ => None,
    };

    let len = data.len() as u64;
    let Ok(mut s) = state.lock() else { return };
    let now = now_unix();
    if let Some((src_mac, dst_mac)) = macs {
        // Both ends are real hosts on this LAN: the sender, and the receiver
        // (which is how a download-heavy device is noticed at all).
        learn_device(&mut s, src_mac, src, len, now);
        learn_device(&mut s, dst_mac, dst, len, now);
    }
    s.observe(
        proto,
        Endpoint {
            ip: src,
            port: sport,
        },
        Endpoint {
            ip: dst,
            port: dport,
        },
        len,
        now,
    );
    attribute(
        &mut s,
        &PacketFacts {
            src,
            dst,
            sport,
            dport,
            len,
            now,
        },
        payload,
    );
}

/// One frame, reduced to the facts worth keeping.
///
/// A struct rather than eight arguments to `attribute`: the caller fills in what
/// the wire said once, and every reader below works from the same fields.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PacketFacts {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    /// The whole frame length, the same measure the device totals use, so the
    /// dashboard and a device's budget cannot disagree about what a byte is.
    pub len: u64,
    pub now: u64,
}

/// The port worth remembering about a conversation.
///
/// Recording whichever end happened to be the source fills the device page with
/// numbers like 51422, which say nothing about what a device is doing. The end
/// that is not an ephemeral client port is the service, and that is the one
/// worth keeping. When neither looks like a service — two peers chatting on high
/// ports — the lower number is the stable one to keep.
fn service_port(sport: u16, dport: u16) -> u16 {
    let ephemeral = |p: u16| p >= 32_768;
    match (ephemeral(sport), ephemeral(dport)) {
        (true, false) => dport,
        (false, true) => sport,
        _ => sport.min(dport),
    }
}

/// Everything a packet says about the devices that carried it: who they talk to,
/// which ports they use, which direction the bytes went, and — for plaintext DNS
/// only — which names they asked for.
pub(crate) fn attribute(s: &mut State, packet: &PacketFacts, payload: &[u8]) {
    // Destructured so that the body below reads exactly as it did when these
    // were eight separate arguments.
    let PacketFacts {
        src,
        dst,
        sport,
        dport,
        len,
        now,
    } = *packet;
    // Read the two facts that need the state before taking a mutable borrow of
    // it: the byte counters and the device lookup both touch the same map.
    let src_is_ours = s.local_ips.contains(&src);
    let dst_is_ours = s.local_ips.contains(&dst);
    // Both ends are told about, but only ever about the port worth knowing.
    let service = service_port(sport, dport);
    if !src_is_ours && s.device_by_ip(src).is_some() {
        note_peer(s, src, dst, len, now);
        note_port(s, src, service, len);
        note_direction(s, src, true, len);
    }
    if !dst_is_ours && s.device_by_ip(dst).is_some() {
        note_peer(s, dst, src, len, now);
        note_port(s, dst, service, len);
        note_direction(s, dst, false, len);
    }
    if !s.read_dns_names || payload.is_empty() {
        return;
    }
    if (sport == PORT_DNS || dport == PORT_DNS || sport == PORT_MDNS || dport == PORT_MDNS)
        && let Some(summary) = dns_summary(payload)
    {
        if summary.is_query {
            if !src_is_ours {
                note_domain(s, src, &summary.name);
            }
        } else {
            if let Some(ip) = summary.answer {
                note_resolved(s, &summary.name, ip);
            }
            if !src_is_ours {
                note_domain(s, src, &summary.name);
            }
        }
    }
}

/// The little of a DNS message that is worth knowing.
pub struct DnsSummary {
    pub name: String,
    pub is_query: bool,
    pub answer: Option<IpAddr>,
}

/// Read the question name out of a DNS message, and the first address it
/// answers with.
///
/// This is the only place any payload byte is looked at, it only ever runs on
/// plaintext DNS and mDNS, and what is kept is the *name* — never the message.
/// Most devices now use encrypted DNS, which tells us nothing, and that limit is
/// stated in the dashboard rather than papered over.
pub fn dns_summary(p: &[u8]) -> Option<DnsSummary> {
    if p.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([*p.get(2)?, *p.get(3)?]);
    let is_query = flags & 0x8000 == 0;
    if u16::from_be_bytes([*p.get(4)?, *p.get(5)?]) == 0 {
        return None;
    }
    let (name, mut offset) = read_name(p, 12)?;
    offset = offset.checked_add(4)?; // qtype + qclass
    let answers = u16::from_be_bytes([*p.get(6)?, *p.get(7)?]);
    let answer = if is_query {
        None
    } else {
        first_address(p, offset, answers)
    };
    Some(DnsSummary {
        name,
        is_query,
        answer,
    })
}

/// Walk the answer records of a response. Two records are plenty: a frame this
/// small rarely carries more, and the name is already known.
fn first_address(p: &[u8], mut offset: usize, answers: u16) -> Option<IpAddr> {
    for _ in 0..answers.min(2) {
        let first = *p.get(offset)?;
        if first & 0xc0 == 0xc0 {
            offset = offset.checked_add(2)?;
        } else {
            let (_, next) = read_name(p, offset)?;
            offset = next;
        }
        let rtype = u16::from_be_bytes([*p.get(offset)?, *p.get(offset.checked_add(1)?)?]);
        let rdlen = u16::from_be_bytes([
            *p.get(offset.checked_add(8)?)?,
            *p.get(offset.checked_add(9)?)?,
        ]);
        offset = offset.checked_add(10)?;
        if rtype == 1 && rdlen == 4 {
            let octets = p.get(offset..offset.checked_add(4)?)?;
            return Some(IpAddr::V4(Ipv4Addr::new(
                octets[0], octets[1], octets[2], octets[3],
            )));
        }
        offset = offset.checked_add(usize::from(rdlen))?;
    }
    None
}

/// A DNS name at `offset`: length-prefixed labels, no compression.
///
/// Compression pointers are refused rather than followed: they point backwards
/// into a message that a 128-byte snaplen may have cut in half, and a name read
/// out of the wrong bytes would be worse than no name at all.
fn read_name(p: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = usize::from(*p.get(offset)?);
        if len == 0 {
            offset = offset.checked_add(1)?;
            break;
        }
        if len & 0xc0 != 0 || len > 63 || labels.len() >= 8 {
            return None;
        }
        let label = p.get(offset.checked_add(1)?..offset.checked_add(1)?.checked_add(len)?)?;
        if !label.iter().all(u8::is_ascii_graphic) {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).to_string());
        offset = offset.checked_add(1)?.checked_add(len)?;
        if labels.iter().map(String::len).sum::<usize>() > 80 {
            return None;
        }
    }
    if labels.is_empty() {
        return None;
    }
    let name = labels.join(".");
    if name.len() > crate::state::MAX_NAME_LEN {
        return None;
    }
    Some((name, offset))
}

//────────────────────────────────────────────────────────── interfaces

pub fn device_addresses(name: &str) -> Vec<IpAddr> {
    pcap::Device::list()
        .ok()
        .and_then(|ds| ds.into_iter().find(|d| d.name == name))
        .map(|d| d.addresses.into_iter().map(|a| a.addr).collect())
        .unwrap_or_default()
}

pub fn pick_device(wanted: Option<&str>) -> Result<String, String> {
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

pub fn list_ifaces() {
    match pcap::Device::list() {
        Ok(devices) => {
            println!("capture interfaces:");
            for d in devices {
                let addrs: Vec<String> = d.addresses.iter().map(|a| a.addr.to_string()).collect();
                println!(
                    "  {:<16} {}",
                    d.name,
                    if addrs.is_empty() {
                        "-".to_string()
                    } else {
                        addrs.join(", ")
                    }
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

//────────────────────────────────────────────────────────── demo

/// Fabricate conversations so the dashboard can be inspected without granting
/// any capability.
///
/// Two address ranges, for two different reasons. The pretend LAN hosts are
/// private addresses, because the device learner refuses anything else — a
/// documentation range here would silently leave the device list empty and the
/// demo would prove nothing about discovery. The pretend *remote* peers are RFC
/// 5737 documentation addresses, so a published repository carries nothing that
/// resembles a real network.
pub fn demo_traffic(state: &Arc<Mutex<State>>) {
    const OURS: Ipv4Addr = Ipv4Addr::new(192, 168, 10, 200);
    let remote = [
        (Ipv4Addr::new(192, 0, 2, 1), 443u16),
        (Ipv4Addr::new(198, 51, 100, 7), 443),
        (Ipv4Addr::new(203, 0, 113, 53), 53),
        (Ipv4Addr::new(198, 51, 100, 20), 80),
        (Ipv4Addr::new(203, 0, 113, 9), 853),
    ];
    // Enough shapes that every badge in the dashboard has something to show: a
    // router, a workstation, a printer, a television, a smart plug — each with a
    // real registry prefix — and a phone, which rotates its private address the
    // way phones do, so the randomised badge and the "likely the same device"
    // hint are both visible.
    let lan: [([u8; 6], u8, Option<&str>); 6] = [
        (
            [0xfc, 0xd7, 0x33, 0x11, 0x22, 0x01],
            1,
            Some("main-router.local"),
        ),
        (
            [0x04, 0xea, 0x56, 0x0a, 0x0b, 0x0c],
            51,
            Some("workstation.local"),
        ),
        (
            [0x48, 0xdf, 0x37, 0xaa, 0xbb, 0xcc],
            61,
            Some("office-printer.local"),
        ),
        (
            [0x00, 0x0d, 0x4b, 0x33, 0x44, 0x55],
            70,
            Some("living-room-tv.local"),
        ),
        (
            [0x3c, 0x71, 0xbf, 0x77, 0x88, 0x99],
            90,
            Some("kitchen-plug.local"),
        ),
        ([0x9a, 0x23, 0x0a, 0x5a, 0x5f, 0xe4], 83, None),
    ];
    let queries = ["cdn.example.com", "time.example.org", "updates.example.net"];
    let mut n: usize = 0;
    loop {
        std::thread::sleep(Duration::from_millis(350));
        let (peer_ip, peer_port) = remote[n % remote.len()];
        let offset = u16::try_from(n % 900).unwrap_or(0);
        let extra = u64::try_from(n % 9000).unwrap_or(0);
        let ours = Endpoint {
            ip: IpAddr::V4(OURS),
            port: 40_000 + offset,
        };
        let peer = Endpoint {
            ip: IpAddr::V4(peer_ip),
            port: peer_port,
        };
        let (mac, last_octet, name) = lan[(n / 4) % lan.len()];
        // The unnamed phone wanders between three addresses, which is exactly
        // the pattern the address-change alert and the duplicate hint exist for.
        let last_octet = if name.is_none() {
            last_octet + u8::try_from((n / 400) % 3).unwrap_or(0)
        } else {
            last_octet
        };
        let lan_ip = Ipv4Addr::new(192, 168, 10, last_octet);
        let now = match state.lock() {
            Ok(s) => now_unix().max(s.started_at),
            Err(_) => return,
        };
        if let Ok(mut s) = state.lock() {
            learn_device(&mut s, mac, IpAddr::V4(lan_ip), 200 + extra, now);
            note_peer(
                &mut s,
                IpAddr::V4(lan_ip),
                IpAddr::V4(peer_ip),
                300 + extra,
                now,
            );
            note_direction(&mut s, IpAddr::V4(lan_ip), true, 120);
            note_direction(&mut s, IpAddr::V4(lan_ip), false, 1400 + extra);
            note_port(&mut s, IpAddr::V4(lan_ip), peer_port, 300 + extra);
            if let Some(name) = name {
                note_domain(&mut s, IpAddr::V4(lan_ip), name);
            }
            note_resolved(&mut s, queries[n % queries.len()], IpAddr::V4(peer_ip));
            s.observe("TCP", ours, peer, 128, now);
            s.observe("TCP", peer, ours, 1400 + extra, now);
            let (packets, bytes) = (s.packets, s.bytes);
            s.series.sample(packets, bytes, now);
        }
        n += 1;
    }
}

/// Report the mode as an enum, so demo traffic can never be mistaken for
/// capture by anything downstream.
#[must_use]
pub fn mode_of(demo: bool) -> Mode {
    if demo { Mode::Demo } else { Mode::Live }
}
