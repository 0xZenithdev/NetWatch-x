//! The device inventory: who is on this network, what they are called, and what
//! they have been doing.
//!
//! Hosts are learned from frames that were already being captured — the source
//! MAC with its source address, plus the destination pair when it belongs to a
//! host. Nothing is scanned, so nothing on this network is disturbed and no scan
//! noise is generated. That is the whole reason this beats an ARP-scanning
//! inventory, and it is also why every claim made here is a *sighting*, never a
//! sweep result.

use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;

use crate::alerts::emit_device_alert;
use crate::state::{
    BUCKETS, MAX_DEVICES, MAX_DOMAINS_PER_DEVICE, MAX_IPS_PER_DEVICE, MAX_PEERS_PER_DEVICE,
    MAX_PORTS_PER_DEVICE, OFFLINE_ALERT_SECS, OFFLINE_REARM_SECS, State, VISUAL_IDLE_SECS,
};

/// One address a device has been seen using, and when.
#[derive(Clone)]
pub struct IpRecord {
    pub ip: IpAddr,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// A remote host this device has talked to.
#[derive(Clone, Default)]
pub struct Peer {
    pub bytes: u64,
    pub packets: u64,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// A stretch of time during which the device was seen.
#[derive(Clone)]
pub struct Session {
    pub start: u64,
    pub end: u64,
}

/// What the operator says a device is, as opposed to what was guessed from its
/// hardware address. Guesses are never allowed to overwrite a decision.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Unknown,
    Router,
    Phone,
    Tablet,
    Laptop,
    Desktop,
    Server,
    Tv,
    Console,
    Printer,
    Camera,
    Speaker,
    Iot,
    Watch,
    Other,
}

impl Kind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Unknown => "unknown",
            Kind::Router => "router",
            Kind::Phone => "phone",
            Kind::Tablet => "tablet",
            Kind::Laptop => "laptop",
            Kind::Desktop => "desktop",
            Kind::Server => "server",
            Kind::Tv => "tv",
            Kind::Console => "console",
            Kind::Printer => "printer",
            Kind::Camera => "camera",
            Kind::Speaker => "speaker",
            Kind::Iot => "iot",
            Kind::Watch => "watch",
            Kind::Other => "other",
        }
    }

    /// The label a person reads.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Kind::Unknown => "Unidentified",
            Kind::Router => "Router or modem",
            Kind::Phone => "Phone",
            Kind::Tablet => "Tablet",
            Kind::Laptop => "Laptop",
            Kind::Desktop => "Desktop PC",
            Kind::Server => "Server",
            Kind::Tv => "TV or streaming box",
            Kind::Console => "Game console",
            Kind::Printer => "Printer",
            Kind::Camera => "Camera",
            Kind::Speaker => "Speaker",
            Kind::Iot => "Smart-home device",
            Kind::Watch => "Watch or wearable",
            Kind::Other => "Other",
        }
    }

    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let all = [
            Kind::Unknown,
            Kind::Router,
            Kind::Phone,
            Kind::Tablet,
            Kind::Laptop,
            Kind::Desktop,
            Kind::Server,
            Kind::Tv,
            Kind::Console,
            Kind::Printer,
            Kind::Camera,
            Kind::Speaker,
            Kind::Iot,
            Kind::Watch,
            Kind::Other,
        ];
        all.into_iter().find(|k| k.as_str() == text)
    }

    /// Every kind, for the dashboard's picker.
    #[must_use]
    pub fn all() -> Vec<Self> {
        vec![
            Kind::Unknown,
            Kind::Router,
            Kind::Phone,
            Kind::Tablet,
            Kind::Laptop,
            Kind::Desktop,
            Kind::Server,
            Kind::Tv,
            Kind::Console,
            Kind::Printer,
            Kind::Camera,
            Kind::Speaker,
            Kind::Iot,
            Kind::Watch,
            Kind::Other,
        ]
    }
}

/// How much attention a device deserves.
///
/// This is the operator's answer to "do I care about this thing?", and it is
/// what keeps an alert channel usable: `Ignored` silences a device completely
/// without weakening the rules for every other device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Trust {
    /// Seen, never acknowledged. These are what the review queue is made of.
    Unknown,
    /// The operator has recognised it.
    Known,
    /// Recognised and expected: alerts about it are informational.
    Trusted,
    /// Deliberately muted. No alerts about this device, at all.
    Ignored,
}

impl Trust {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Trust::Unknown => "unknown",
            Trust::Known => "known",
            Trust::Trusted => "trusted",
            Trust::Ignored => "ignored",
        }
    }

    /// The sentence shown next to the setting, because "trusted" alone does not
    /// tell anyone what it changes.
    #[must_use]
    pub fn explain(self) -> &'static str {
        match self {
            Trust::Unknown => "Not yet reviewed. Counted in the review queue.",
            Trust::Known => "You have recognised this device.",
            Trust::Trusted => "Expected on this network. Alerts about it are informational.",
            Trust::Ignored => "Muted: no alerts about this device at all.",
        }
    }

    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "unknown" => Some(Trust::Unknown),
            "known" => Some(Trust::Known),
            "trusted" => Some(Trust::Trusted),
            "ignored" => Some(Trust::Ignored),
            _ => None,
        }
    }
}

/// One device's counters for the current UTC day.
///
/// The keeper writes the difference between this and `flushed` into the history
/// database every thirty seconds, so a day accumulates in memory and only a few
/// upserts reach the disk.
#[derive(Clone, Copy, Default)]
pub struct DayCounters {
    pub day: u64,
    pub up: u64,
    pub down: u64,
    pub packets: u64,
    pub online_secs: u64,
    pub sessions: u64,
}

/// How loudly a device is allowed to interrupt the operator.
///
/// Enforced where the alert is raised, not where it is delivered: a muted alert
/// still lands in the dashboard and the spool, because that is the record, and
/// the notifier skips it. Quiet means "only things that need action" — a MAC
/// conflict, a capture failure — and never means nothing leaves the box.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Notify {
    #[default]
    Default,
    Quiet,
    Never,
}

impl Notify {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Quiet => "quiet",
            Self::Never => "never",
        }
    }

    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "default" | "all" | "everything" => Some(Self::Default),
            "quiet" | "important" => Some(Self::Quiet),
            "never" | "off" | "none" => Some(Self::Never),
            _ => None,
        }
    }

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Default => "Everything worth telling you",
            Self::Quiet => "Only things that need action",
            Self::Never => "Nothing — dashboard only",
        }
    }

    /// Whether an alert of this severity should reach the operator's phone.
    #[must_use]
    pub fn allows(self, severity: &str) -> bool {
        match self {
            Self::Default => true,
            Self::Quiet => severity == "alert",
            Self::Never => false,
        }
    }
}

/// A host seen on the wire, identified by its hardware address.
pub struct Device {
    pub mac: [u8; 6],
    pub ips: Vec<IpRecord>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub packets: u64,
    pub bytes: u64,
    pub up_bytes: u64,
    pub down_bytes: u64,
    pub online: bool,
    pub offline_since: Option<u64>,
    pub sessions: u64,
    pub session_start: u64,
    pub last_offline_alert: u64,
    pub last_conflict_alert: u64,
    pub last_spike_alert: u64,
    /// The operator's name for it. The one label nothing else may overwrite.
    pub name: Option<String>,
    /// A name read off the wire (mDNS). Always a suggestion, never a decision.
    pub auto_name: Option<String>,
    pub vendor: Option<String>,
    pub kind: Option<Kind>,
    pub kind_guess: Option<Kind>,
    pub trust: Trust,
    pub notes: String,
    pub peers: BTreeMap<IpAddr, Peer>,
    pub ports: BTreeMap<u16, u64>,
    pub domains: BTreeMap<String, u64>,
    /// Bytes per minute, newest last, always ending at `bucket_at`.
    pub buckets: VecDeque<u64>,
    pub bucket_at: u64,
    pub timeline: VecDeque<Session>,
    /// This device's counters for the current UTC day, and the watermark the
    /// last flush to the history database left behind.
    pub day: DayCounters,
    pub flushed: DayCounters,
    /// A daily budget in bytes, if the operator set one.
    pub quota_bytes: Option<u64>,
    /// How loudly this device may interrupt the operator.
    pub notify: Notify,
    /// The day a quota alert was last raised for, so it fires once a day.
    pub quota_alerted_day: u64,
}

impl Device {
    /// What to call this device in a list, in order of who decided it: the
    /// operator, then the wire, then the maker, then nothing.
    #[must_use]
    pub fn display_name(&self) -> Option<String> {
        self.name
            .clone()
            .or_else(|| self.auto_name.clone())
            .or_else(|| self.vendor.clone())
    }

    #[must_use]
    pub fn primary_ip(&self) -> Option<IpAddr> {
        self.ips.iter().max_by_key(|r| r.last_seen).map(|r| r.ip)
    }

    #[must_use]
    pub fn vendor_name(&self) -> Option<&str> {
        self.vendor.as_deref()
    }

    /// The kind in force: what the operator said, else what the vendor suggests.
    #[must_use]
    pub fn effective_kind(&self) -> Option<Kind> {
        self.kind.or(self.kind_guess)
    }

    #[must_use]
    pub fn is_randomized(&self) -> bool {
        is_randomized(self.mac)
    }

    /// Whether this device has been reviewed by the operator.
    #[must_use]
    pub fn needs_review(&self) -> bool {
        self.trust == Trust::Unknown
    }

    /// Bytes per minute for the last [`BUCKETS`] minutes, gaps filled, so the
    /// dashboard can draw it without knowing when the device was last seen.
    #[must_use]
    pub fn sparkline(&self, now: u64) -> Vec<u64> {
        let now_minute = now / 60;
        let mut out: Vec<u64> = vec![0; BUCKETS];
        if self.bucket_at == 0 {
            return out;
        }
        let newest = self.bucket_at;
        for (i, value) in self.buckets.iter().enumerate() {
            let minute =
                newest.saturating_sub(u64::try_from(self.buckets.len() - 1 - i).unwrap_or(0));
            let offset = now_minute.saturating_sub(minute);
            if offset == 0 {
                if let Some(slot) = out.last_mut() {
                    *slot += value;
                }
            } else if offset < BUCKETS as u64 {
                let idx = BUCKETS - 1 - usize::try_from(offset).unwrap_or(0);
                out[idx] += value;
            }
        }
        out
    }

    /// Median bytes over the last hour of *active* minutes — this device's own
    /// baseline. Comparing a device to itself is the only comparison that does
    /// not produce nonsense on a mixed network.
    #[must_use]
    fn baseline(&self) -> u64 {
        let mut values: Vec<u64> = self.buckets.iter().copied().filter(|v| *v > 0).collect();
        if values.is_empty() {
            return 0;
        }
        values.sort_unstable();
        values[values.len() / 2]
    }
}

//────────────────────────────────────────────────────────── address rules

const MAC_CONFLICT_WINDOW: u64 = 600;
const SPIKE_FACTOR: u64 = 8;
const SPIKE_FLOOR_BYTES: u64 = 2_000_000;
const SPIKE_REARM_SECS: u64 = 3600;
pub const MAX_NAME_CHARS: usize = 48;
pub const MAX_NOTES_CHARS: usize = 280;

#[must_use]
pub fn mac_string(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Parse `aa:bb:cc:dd:ee:ff`, accepting dashes and odd casing.
#[must_use]
pub fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let normalised = text.trim().to_lowercase().replace('-', ":");
    let parts: Vec<&str> = normalised.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        if part.len() > 2 {
            return None;
        }
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

/// Addresses that can belong to a host on this network: private IPv4,
/// link-local, IPv6 unique-local and IPv6 link-local.
///
/// `172.67.219.2` and `172.217.112.4` are Cloudflare and Google, not private
/// addresses — only 172.16.0.0/12 is — which is exactly the mistake live
/// traffic caught here.
#[must_use]
pub fn is_lan_address(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let head = v6.segments()[0];
            head & 0xfe00 == 0xfc00 || head & 0xffc0 == 0xfe80
        }
    }
}

/// MACs that cannot belong to a host: broadcast, multicast, or all zero.
#[must_use]
pub fn is_host_mac(mac: [u8; 6]) -> bool {
    mac != [0u8; 6] && mac[0] & 1 == 0
}

/// Whether the address is locally administered, which is what a phone's private
/// Wi-Fi address is. Bit 1 of the first octet.
///
/// This matters far more than it sounds: over half the devices on this network
/// are randomised, so the same phone appears as a brand new device whenever it
/// rotates its address, and a device that looks like an intruder is usually just
/// a phone protecting itself.
#[must_use]
pub fn is_randomized(mac: [u8; 6]) -> bool {
    mac[0] & 0x02 != 0
}

/// Addresses that are not a peer worth recording: the unspecified address,
/// loopback, broadcast, and multicast (`224/4`, `ff00::/8`). A device does not
/// have a conversation with a multicast group.
#[must_use]
pub fn is_recordable_peer(ip: &IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => !v4.is_multicast() && !v4.is_broadcast(),
        IpAddr::V6(v6) => !v6.is_multicast(),
    }
}

//────────────────────────────────────────────────────────── learning

/// Outcome of folding a sighting into an existing device, so the caller can
/// raise alerts without holding a borrow of the device map.
#[derive(Default, Clone, Copy)]
struct Touch {
    came_back: bool,
    new_address: bool,
    first_address: Option<IpAddr>,
}

/// Record a sighting of a device, raising an alert the first time a MAC is seen.
///
/// A MAC that has never been seen before means a device joined the network;
/// noticing that is the core of an intruder detector, and because this box is
/// the gateway it gets the sighting for free.
pub fn learn_device(s: &mut State, mac: [u8; 6], ip: IpAddr, len: u64, now: u64) {
    if !is_host_mac(mac) || !is_lan_address(&ip) || s.local_ips.contains(&ip) {
        return;
    }
    if let Some(d) = s.devices.get_mut(&mac) {
        let touch = touch(d, ip, len, now);
        emit_transitions(s, mac, touch, now);
        note_ownership(s, mac, ip, now);
        s.dirty = true;
        return;
    }
    // Create first, then note ownership: a conflict alert names both holders, so
    // the newcomer has to exist before the claim is recorded.
    create_device(s, mac, ip, len, now);
    note_ownership(s, mac, ip, now);
}

/// Remember which hardware address is using an address, and complain when two
/// are using it at once.
fn note_ownership(s: &mut State, mac: [u8; 6], ip: IpAddr, now: u64) {
    let previous = s.ip_owners.insert(ip, (mac, now));
    let Some((other, at)) = previous else { return };
    if other == mac || now.saturating_sub(at) > MAC_CONFLICT_WINDOW {
        return;
    }
    // Two MACs on one address inside ten minutes. Alert on the newcomer and on
    // the previous holder, so neither is silently credited as "the" device.
    for candidate in [mac, other] {
        let Some(d) = s.devices.get(&candidate) else {
            continue;
        };
        if now.saturating_sub(d.last_conflict_alert) < SPIKE_REARM_SECS {
            continue;
        }
        if let Some(d) = s.devices.get_mut(&candidate) {
            d.last_conflict_alert = now;
        }
        emit_device_alert(
            s,
            candidate,
            "mac_conflict",
            "alert",
            &format!("address {ip} is in use by more than one device"),
            &[(
                "other device",
                &mac_string(if candidate == mac { other } else { mac }),
            )],
        );
    }
}

fn touch(d: &mut Device, ip: IpAddr, len: u64, now: u64) -> Touch {
    let mut touch = Touch::default();
    if !d.online {
        d.online = true;
        d.offline_since = None;
        d.session_start = now;
        touch.came_back = true;
    }
    d.last_seen = now;
    d.packets += 1;
    d.bytes += len;
    d.day.packets += 1;
    bucket_add(d, now, len);
    if let Some(record) = d.ips.iter_mut().find(|r| r.ip == ip) {
        record.last_seen = now;
        // A device can be seen sending from an address we already know and, in
        // the same breath, be seen *receiving* on one. Only a genuinely new
        // address is announced, so the log does not report the obvious.
        return touch;
    }
    if d.ips.len() < MAX_IPS_PER_DEVICE {
        d.ips.push(IpRecord {
            ip,
            first_seen: now,
            last_seen: now,
        });
        touch.new_address = true;
        touch.first_address = Some(ip);
    }
    touch
}

fn emit_transitions(s: &mut State, mac: [u8; 6], touch: Touch, now: u64) {
    if touch.came_back {
        // Only worth saying if the operator was told it went away: otherwise
        // this is a phone waking up, which nobody needs a message about.
        let announced = s.devices.get(&mac).is_some_and(|d| {
            d.last_offline_alert > 0
                && now.saturating_sub(d.last_offline_alert) < OFFLINE_REARM_SECS
        });
        if announced {
            emit_device_alert(
                s,
                mac,
                "device_back_online",
                "info",
                "it is transmitting again",
                &[],
            );
        }
    }
    if let Some(ip) = touch.first_address
        && touch.new_address
    {
        let previous = s
            .devices
            .get(&mac)
            .and_then(|d| {
                d.ips
                    .iter()
                    .filter(|r| r.ip != ip)
                    .max_by_key(|r| r.last_seen)
            })
            .map_or_else(|| "unknown".to_string(), |r| r.ip.to_string());
        emit_device_alert(
            s,
            mac,
            "address_change",
            "notable",
            &format!("now also using {ip}"),
            &[("previous address", &previous)],
        );
    }
}

fn create_device(s: &mut State, mac: [u8; 6], ip: IpAddr, len: u64, now: u64) {
    if s.devices.len() >= MAX_DEVICES {
        evict_one(s);
    }
    let vendor = crate::oui::vendor_for(mac).map(ToString::to_string);
    let kind_guess = vendor.as_deref().and_then(guess_kind);
    let duplicate = possible_duplicate(s, mac, ip, now);
    let mut buckets = VecDeque::new();
    buckets.push_back(0);
    s.devices.insert(
        mac,
        Device {
            mac,
            ips: vec![IpRecord {
                ip,
                first_seen: now,
                last_seen: now,
            }],
            first_seen: now,
            last_seen: now,
            packets: 1,
            bytes: len,
            up_bytes: 0,
            down_bytes: 0,
            online: true,
            offline_since: None,
            sessions: 1,
            session_start: now,
            last_offline_alert: 0,
            last_conflict_alert: 0,
            last_spike_alert: 0,
            name: None,
            auto_name: None,
            vendor,
            kind: None,
            kind_guess,
            trust: Trust::Unknown,
            notes: String::new(),
            peers: BTreeMap::new(),
            ports: BTreeMap::new(),
            domains: BTreeMap::new(),
            buckets,
            bucket_at: now / 60,
            timeline: VecDeque::new(),
            day: DayCounters {
                day: crate::history::day_of(now),
                // The packet that created this device is a packet it sent; the
                // direction is not known yet, so only the count is claimed.
                packets: 1,
                ..DayCounters::default()
            },
            flushed: DayCounters {
                day: crate::history::day_of(now),
                ..DayCounters::default()
            },
            quota_bytes: None,
            notify: Notify::Default,
            quota_alerted_day: 0,
        },
    );
    let mut extra: Vec<(String, String)> = Vec::new();
    if let Some(v) = s.devices.get(&mac).and_then(Device::vendor_name) {
        extra.push(("maker".into(), v.to_string()));
    }
    if is_randomized(mac) {
        extra.push((
            "note".into(),
            "randomised address — phones rotate these, so this may be a device you already know"
                .into(),
        ));
    }
    if let Some(other) = duplicate {
        extra.push(("possibly the same device as".into(), mac_string(other)));
    }
    let refs: Vec<(&str, &str)> = extra
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    emit_device_alert(
        s,
        mac,
        "new_device",
        "alert",
        &format!("first sighting on this network at {ip}"),
        &refs,
    );
}

/// Drop the least interesting device when the inventory is full: an unnamed,
/// unreviewed device that has been quiet longest. A device the operator has
/// named or reviewed is never evicted, because that decision is not the
/// daemon's to throw away.
fn evict_one(s: &mut State) {
    let victim = s
        .devices
        .values()
        .filter(|d| d.name.is_none() && d.trust == Trust::Unknown)
        .min_by_key(|d| d.last_seen)
        .map(|d| d.mac);
    let Some(mac) = victim else { return };
    s.devices.remove(&mac);
    s.ip_owners.retain(|_, (owner, _)| *owner != mac);
}

/// Another device that used the same address and was never online at the same
/// time. That is the signature of one phone rotating its private address, and
/// saying so is far more useful than listing it as two strangers.
///
/// `since`/`last_seen` describe the device being asked about, so this can be
/// asked about a device before it is inserted into the inventory.
#[must_use]
pub fn possible_duplicate(s: &State, mac: [u8; 6], ip: IpAddr, since: u64) -> Option<[u8; 6]> {
    s.devices
        .values()
        .filter(|d| d.mac != mac)
        .filter(|d| d.ips.iter().any(|r| r.ip == ip))
        .filter(|d| d.last_seen <= since || since <= d.first_seen)
        .max_by_key(|d| d.last_seen)
        .map(|d| d.mac)
}

/// Fold a packet into the per-minute bucket the device's history is made of.
fn bucket_add(d: &mut Device, now: u64, len: u64) {
    let minute = now / 60;
    if d.bucket_at == 0 {
        d.bucket_at = minute;
        d.buckets.clear();
        d.buckets.push_back(0);
    }
    if minute < d.bucket_at {
        return; // a clock that went backwards is not worth a rewrite of history
    }
    if minute - d.bucket_at >= BUCKETS as u64 {
        d.buckets.clear();
        d.buckets.push_back(0);
        d.bucket_at = minute;
    }
    while d.bucket_at < minute {
        d.buckets.push_back(0);
        while d.buckets.len() > BUCKETS {
            d.buckets.pop_front();
        }
        d.bucket_at += 1;
    }
    if let Some(slot) = d.buckets.back_mut() {
        *slot += len;
    }
}

/// Record what a device said to a remote host.
pub fn note_peer(s: &mut State, device_ip: IpAddr, peer: IpAddr, len: u64, now: u64) {
    if !is_recordable_peer(&peer) || peer == device_ip {
        return;
    }
    let Some(mac) = s.device_by_ip(device_ip) else {
        return;
    };
    let Some(d) = s.devices.get_mut(&mac) else {
        return;
    };
    if let Some(entry) = d.peers.get_mut(&peer) {
        entry.bytes += len;
        entry.packets += 1;
        entry.last_seen = now;
        return;
    }
    if d.peers.len() >= MAX_PEERS_PER_DEVICE {
        // Keep the conversation this device actually uses: drop the least
        // recently active peer rather than refusing to learn a new one.
        let coldest = d
            .peers
            .iter()
            .min_by_key(|(_, p)| p.last_seen)
            .map(|(ip, _)| *ip);
        if let Some(ip) = coldest {
            d.peers.remove(&ip);
        }
    }
    d.peers.insert(
        peer,
        Peer {
            bytes: len,
            packets: 1,
            first_seen: now,
            last_seen: now,
        },
    );
}

/// Record a port a device used. Ports are how "what is this device doing" gets
/// an answer a person can read: 443 is encrypted web, 5353 is local discovery.
pub fn note_port(s: &mut State, device_ip: IpAddr, port: u16, len: u64) {
    if port == 0 {
        return;
    }
    let Some(mac) = s.device_by_ip(device_ip) else {
        return;
    };
    let Some(d) = s.devices.get_mut(&mac) else {
        return;
    };
    if let Some(bytes) = d.ports.get_mut(&port) {
        *bytes += len;
        return;
    }
    if d.ports.len() >= MAX_PORTS_PER_DEVICE {
        let coldest = d
            .ports
            .iter()
            .min_by_key(|(_, bytes)| **bytes)
            .map(|(p, _)| *p);
        if let Some(p) = coldest {
            d.ports.remove(&p);
        }
    }
    d.ports.insert(port, len);
}

/// Record which way the bytes went for a local device.
pub fn note_direction(s: &mut State, device_ip: IpAddr, egress: bool, len: u64) {
    let Some(mac) = s.device_by_ip(device_ip) else {
        return;
    };
    let Some(d) = s.devices.get_mut(&mac) else {
        return;
    };
    if egress {
        d.up_bytes += len;
        d.day.up += len;
    } else {
        d.down_bytes += len;
        d.day.down += len;
    }
}

/// Record a domain a device asked about, and — for `.local` names — offer it as
/// a suggested name.
///
/// Names are only ever read from plaintext DNS. Most traffic is TLS, and a
/// device using encrypted DNS tells us nothing at all, which is a limit worth
/// stating rather than hiding.
pub fn note_domain(s: &mut State, device_ip: IpAddr, name: &str) {
    if name.len() > crate::state::MAX_NAME_LEN || name.is_empty() {
        return;
    }
    let lower = name.to_lowercase();
    let Some(mac) = s.device_by_ip(device_ip) else {
        return;
    };
    if let Some(label) = local_name_label(name)
        && let Some(d) = s.devices.get_mut(&mac)
        && d.auto_name.is_none()
        && d.name.is_none()
    {
        d.auto_name = Some(label);
        s.dirty = true;
    }
    let Some(d) = s.devices.get_mut(&mac) else {
        return;
    };
    if let Some(count) = d.domains.get_mut(&lower) {
        *count += 1;
        return;
    }
    if d.domains.len() < MAX_DOMAINS_PER_DEVICE {
        d.domains.insert(lower, 1);
    }
}

/// `living-room-tv.local.` becomes `Living-room-tv`, which is a name a person
/// recognises in a list.
fn local_name_label(name: &str) -> Option<String> {
    let trimmed = name.trim_end_matches('.');
    let host = trimmed.strip_suffix(".local")?;
    if host.is_empty() || host.len() > 40 || host.contains('.') {
        return None;
    }
    Some(host.to_string())
}

/// Record an address that a name resolved to, so destination addresses in the
/// dashboard can be shown as names.
pub fn note_resolved(s: &mut State, name: &str, ip: IpAddr) {
    if name.len() > crate::state::MAX_NAME_LEN || name.is_empty() {
        return;
    }
    s.hostnames
        .insert(ip, name.trim_end_matches('.').to_lowercase());
}

//────────────────────────────────────────────────────────── sweep

/// Retire devices that have gone quiet and raise the alert once, with a re-arm
/// window so a flapping device cannot flood the channel.
///
/// Runs from a timer as well as from traffic, because a device that is gone
/// sends no packets to sweep it.
pub fn sweep_devices(s: &mut State, now: u64) {
    let mut offline: Vec<[u8; 6]> = Vec::new();
    for d in s.devices.values_mut() {
        let silent = now.saturating_sub(d.last_seen);
        if d.online && silent > VISUAL_IDLE_SECS {
            d.online = false;
            d.offline_since = Some(now);
            d.sessions += 1;
            let (start, end) = (d.session_start, d.last_seen);
            if end > start {
                push_session(d, start, end);
            }
        }
        // The alert is about silence, not about the moment the dashboard stopped
        // drawing the device as present. It fires on the first sweep after
        // fifteen minutes of quiet, however the display got there — otherwise a
        // device that fell quiet at minute five would never be alerted about at
        // all, because the transition had already happened.
        if !d.online && silent >= OFFLINE_ALERT_SECS {
            offline.push(d.mac);
        }
    }
    for mac in offline {
        let Some(d) = s.devices.get(&mac) else {
            continue;
        };
        if now.saturating_sub(d.last_offline_alert) < OFFLINE_REARM_SECS {
            continue;
        }
        let silent = now.saturating_sub(d.last_seen);
        let detail = format!(
            "nothing seen for {} — it was online before that",
            humanise_secs(silent)
        );
        if let Some(d) = s.devices.get_mut(&mac) {
            d.last_offline_alert = now;
        }
        emit_device_alert(s, mac, "device_offline", "notable", &detail, &[]);
    }
    check_spikes(s, now);
}

fn push_session(d: &mut Device, start: u64, end: u64) {
    d.timeline.push_back(Session { start, end });
    while d.timeline.len() > 24 {
        d.timeline.pop_front();
    }
}

/// Alert when a device moves far more than it usually does. Compared against
/// its own median, never against other devices, and rate-limited to once an
/// hour, because a big download is not an incident.
fn check_spikes(s: &mut State, now: u64) {
    let candidates: Vec<[u8; 6]> = s
        .devices
        .values()
        .filter(|d| now.saturating_sub(d.last_spike_alert) > SPIKE_REARM_SECS)
        .filter(|d| d.buckets.len() >= 2)
        .map(|d| d.mac)
        .collect();
    for mac in candidates {
        let Some(d) = s.devices.get(&mac) else {
            continue;
        };
        // Only a bucket whose minute has finished is a complete minute of
        // traffic; the newest one is still filling and would under-read.
        let current_minute = now / 60;
        let last_full = if d.bucket_at < current_minute {
            d.buckets.back().copied()
        } else {
            d.buckets.iter().rev().nth(1).copied()
        };
        let Some(last_full) = last_full else {
            continue;
        };
        let baseline = d.baseline();
        if last_full < SPIKE_FLOOR_BYTES
            || baseline == 0
            || last_full < baseline.saturating_mul(SPIKE_FACTOR)
        {
            continue;
        }
        if let Some(d) = s.devices.get_mut(&mac) {
            d.last_spike_alert = now;
        }
        let detail = format!(
            "{} in one minute, against a usual {}",
            humanise_bytes(last_full),
            humanise_bytes(baseline)
        );
        emit_device_alert(s, mac, "traffic_spike", "notable", &detail, &[]);
    }
}

//────────────────────────────────────────────────────────── operator edits

/// An edit the operator made in the dashboard. Every field is optional: the
/// dashboard sends only what changed.
#[derive(Default)]
pub struct Edit {
    pub name: Option<String>,
    pub kind: Option<String>,
    pub trust: Option<String>,
    pub notes: Option<String>,
    /// A daily budget in gigabytes, as text. Empty or "0" clears it.
    pub quota_gb: Option<String>,
    /// `default`, `quiet` or `never`.
    pub notify: Option<String>,
}

/// "5" or "5.5" gigabytes, as bytes.
///
/// Parsed with integers rather than floats: a budget that rounds to a strange
/// number is a bug report waiting to happen, and one decimal place is as much
/// precision as a daily budget can mean.
fn parse_gb(text: &str) -> Result<u64, String> {
    const GIB: u64 = 1_073_741_824;
    let text = text.trim();
    let (whole, frac) = text.split_once('.').unwrap_or((text, ""));
    if frac.contains('.') || frac.len() > 1 {
        return Err("give at most one decimal place, e.g. 5.5".into());
    }
    let whole: u64 = whole
        .parse()
        .map_err(|_| format!("'{text}' is not a number of gigabytes"))?;
    let tenth: u64 = if frac.is_empty() {
        0
    } else {
        frac.parse()
            .map_err(|_| format!("'{text}' is not a number of gigabytes"))?
    };
    if whole > 100_000 {
        return Err("a daily budget must be under 100000 GB".into());
    }
    Ok(whole * GIB + tenth * GIB / 10)
}

/// Apply an edit, refusing values that are not meaningful.
///
/// Validation lives here rather than in the HTTP layer so that the rules cannot
/// be bypassed by a second caller.
pub fn apply_edit(s: &mut State, mac: [u8; 6], edit: &Edit) -> Result<(), String> {
    let name = edit.name.as_ref().map(|n| n.trim().to_string());
    if let Some(n) = &name {
        if n.chars().count() > MAX_NAME_CHARS {
            return Err(format!("name is longer than {MAX_NAME_CHARS} characters"));
        }
        if n.chars().any(char::is_control) {
            return Err("name contains control characters".into());
        }
    }
    if let Some(notes) = &edit.notes
        && notes.chars().count() > MAX_NOTES_CHARS
    {
        return Err(format!(
            "notes are longer than {MAX_NOTES_CHARS} characters"
        ));
    }
    let kind = match edit.kind.as_deref() {
        None | Some("") => None,
        Some(k) => Some(Kind::parse(k).ok_or_else(|| format!("unknown device kind '{k}'"))?),
    };
    let trust = match edit.trust.as_deref() {
        None => None,
        Some(t) => Some(Trust::parse(t).ok_or_else(|| format!("unknown trust setting '{t}'"))?),
    };
    let quota = match edit.quota_gb.as_deref() {
        None => None,
        Some("" | "0") => Some(0),
        Some(text) => Some(parse_gb(text)?),
    };
    let notify = match edit.notify.as_deref() {
        None | Some("") => None,
        Some(n) => {
            Some(Notify::parse(n).ok_or_else(|| format!("unknown notification setting '{n}'"))?)
        }
    };
    let Some(d) = s.devices.get_mut(&mac) else {
        return Err("no such device".into());
    };
    if let Some(n) = name {
        d.name = if n.is_empty() { None } else { Some(n) };
    }
    if let Some(k) = kind {
        d.kind = Some(k);
    }
    if let Some(t) = trust {
        d.trust = t;
    }
    if let Some(n) = &edit.notes {
        d.notes.clone_from(n);
    }
    if let Some(bytes) = quota {
        d.quota_bytes = if bytes == 0 { None } else { Some(bytes) };
        // Changing the budget re-arms the alert: a device already over a new,
        // lower budget should say so today rather than staying quiet until
        // tomorrow.
        d.quota_alerted_day = 0;
    }
    if let Some(n) = notify {
        d.notify = n;
    }
    // Any edit counts as a review: naming a device is the operator saying "I
    // know what this is", and leaving it in the review queue after that would
    // make the queue lie.
    if d.trust == Trust::Unknown && (d.name.is_some() || d.kind.is_some()) {
        d.trust = Trust::Known;
    }
    s.dirty = true;
    Ok(())
}

/// "892 MB" — for a sentence a person reads, not for a table.
///
/// Scaled in tenths so 1536 KB reads as "1.5 MB" rather than being truncated to
/// "1.0 MB" by an integer division.
#[must_use]
pub fn humanise_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut tenths = u128::from(n) * 10;
    let mut unit = 0;
    while tenths >= 1024 * 10 && unit + 1 < UNITS.len() {
        tenths /= 1024;
        unit += 1;
    }
    let whole = tenths / 10;
    let frac = tenths % 10;
    if unit == 0 {
        format!("{whole} {}", UNITS[unit])
    } else {
        format!("{whole}.{frac} {}", UNITS[unit])
    }
}

/// "3h 12m" — for humans, not for machines.
#[must_use]
pub fn humanise_secs(secs: u64) -> String {
    let d = secs / 86_400;
    let h = secs % 86_400 / 3600;
    let m = secs % 3600 / 60;
    let s = secs % 60;
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

//────────────────────────────────────────────────────────── vendor guesses

/// A guess at what a device is, from who made it. Always labelled as a guess in
/// the dashboard: an Espressif chip is *probably* a smart plug, but the operator
/// gets to say what it actually is.
fn guess_kind(vendor: &str) -> Option<Kind> {
    let v = vendor.to_lowercase();
    let table: [(&str, Kind); 26] = [
        ("espressif", Kind::Iot),
        ("tuya", Kind::Iot),
        ("shelly", Kind::Iot),
        ("sonoff", Kind::Iot),
        ("itead", Kind::Iot),
        ("philips", Kind::Iot),
        ("signify", Kind::Iot),
        ("roborock", Kind::Iot),
        ("amazon", Kind::Speaker),
        ("sonos", Kind::Speaker),
        ("roku", Kind::Tv),
        ("vizio", Kind::Tv),
        ("hisense", Kind::Tv),
        ("nintendo", Kind::Console),
        ("sony interactive", Kind::Console),
        ("microsoft", Kind::Console),
        ("raspberry", Kind::Server),
        ("ubiquiti", Kind::Router),
        ("tp-link", Kind::Router),
        ("netgear", Kind::Router),
        ("cudy", Kind::Router),
        ("draytek", Kind::Router),
        ("synology", Kind::Server),
        ("hewlett", Kind::Printer),
        ("brother", Kind::Printer),
        ("hikvision", Kind::Camera),
    ];
    table
        .into_iter()
        .find(|(needle, _)| v.contains(needle))
        .map(|(_, kind)| kind)
}

/// Every port label a person might need, so "3478" does not have to be looked up.
#[must_use]
pub fn port_label(port: u16) -> &'static str {
    match port {
        20 | 21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "mail",
        53 => "dns",
        67 | 68 => "dhcp",
        80 => "http",
        123 => "ntp (clock sync)",
        135 => "windows rpc",
        137..=139 => "netbios",
        143 => "imap",
        161 | 162 => "snmp",
        389 => "ldap",
        443 => "https",
        445 => "windows file sharing",
        465 | 587 => "mail submission",
        500 => "ipsec vpn",
        514 => "syslog",
        631 => "printing",
        853 => "dns over tls",
        993 => "imap over tls",
        1194 => "openvpn",
        1883 => "mqtt",
        1900 => "upnp discovery",
        3306 => "mysql",
        3478 | 5349 => "stun / turn (calls)",
        41641 => "tailscale",
        4500 => "nat-t vpn",
        5060 | 5061 => "sip (calls)",
        5228..=5230 => "google push",
        5353 => "mdns (local discovery)",
        5432 => "postgres",
        6379 => "redis",
        8000 | 8080 => "http alternate",
        8443 => "https alternate",
        8883 => "mqtt over tls",
        9100 => "printer raw",
        8725 => "zf dashboard",
        8790 => "netwatch",
        10000 => "webmin",
        32400 => "plex",
        _ => "",
    }
}

/// Devices that should be reviewed, newest first. The review queue.
#[must_use]
pub fn review_queue(s: &State) -> Vec<[u8; 6]> {
    let mut queue: Vec<&Device> = s.devices.values().filter(|d| d.needs_review()).collect();
    queue.sort_by_key(|d| std::cmp::Reverse(d.last_seen));
    queue.into_iter().map(|d| d.mac).collect()
}
