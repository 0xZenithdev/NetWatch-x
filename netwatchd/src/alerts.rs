//! Alerts: what the daemon considers worth telling a human, and the spool it
//! writes them to.
//!
//! Alerts are held in memory for the API and appended to a spool file that a
//! separate notifier delivers. Keeping delivery out of this process means the
//! daemon needs no HTTP or TLS stack at all, and a Telegram outage can never
//! stall packet capture.

use std::io::Write;

use crate::state::{State, now_unix};

/// An event worth telling a human about.
#[derive(Clone)]
pub struct Alert {
    pub ts: u64,
    pub kind: &'static str,
    pub severity: &'static str,
    pub subject: String,
    pub detail: String,
    /// The device this is about, when it is about one. Lets the dashboard link
    /// an alert to the device page instead of leaving a bare MAC address.
    pub mac: Option<String>,
    /// The device's friendly name at the moment the alert fired. Kept in the
    /// alert itself so renaming a device later cannot rewrite history.
    pub name: Option<String>,
    /// What the device's address was, since that is how the reader recognises it.
    pub address: Option<String>,
    /// True when the device's own notification rule says "do not interrupt me".
    ///
    /// The alert is still recorded and still visible in the dashboard; this only
    /// tells the notifier to skip it. Silencing a device should mean you stop
    /// being paged, not that the evidence stops being collected.
    pub muted: bool,
}

impl Alert {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ts": self.ts,
            "kind": self.kind,
            "severity": self.severity,
            "subject": self.subject,
            "detail": self.detail,
            "why": explain(self.kind),
            "mac": self.mac,
            "name": self.name,
            "address": self.address,
            "muted": self.muted,
        })
    }
}

/// How many alerts stay in memory (and therefore in the API payload).
pub const ALERT_MEMORY: usize = 500;

/// Plain-language answer to "why did this fire?".
///
/// The dashboard shows this next to every alert. An alert whose reasoning the
/// operator cannot check is a liability: they either ignore alerts or, worse,
/// act on one they have misread.
#[must_use]
pub fn explain(kind: &str) -> &'static str {
    match kind {
        "new_device" => {
            "A hardware address was seen on this network for the first time since Netwatch \
             started keeping records. That is a fact from the wire, not proof of an intruder: \
             guest phones, a new gadget, or a phone that rotates its private address all look \
             the same. Name it if you recognise it, or set it to Ignored to silence it."
        }
        "device_offline" => {
            "Nothing at all was seen from this device for 15 minutes, after it had been online. \
             Sleepy phones and devices with power-saving Wi-Fi do this all day. Netwatch waits \
             and then stays quiet for six hours per device, so one flapping phone cannot flood \
             you."
        }
        "device_back_online" => "The device transmitted again after being reported offline.",
        "address_change" => {
            "A device Netwatch already knows used a different address. Almost always DHCP \
             handing out a new lease. It would also happen if someone moved a device's address \
             by hand, which is why it is worth a line in the log."
        }
        "mac_conflict" => {
            "One address was used by two different hardware addresses at nearly the same time. \
             The ordinary cause is a DHCP lease being handed from one device to another. The \
             other cause is a device claiming an address that is not its own — so this is worth \
             knowing, but it is not by itself proof of anything."
        }
        "new_peer" => {
            "This device contacted a remote address it has not contacted before, since Netwatch \
             started. Normal internet use does this often, which is why it is reported at the \
             lowest severity and off by default in delivery."
        }
        "traffic_spike" => {
            "This device moved far more data in the last minute than its own recent average. \
             A backup, a game update or a video will do this. Netwatch compares a device only to \
             itself, never to other devices."
        }
        "quota_exceeded" => {
            "This device has moved more than the daily budget you set for it. The figure comes \
             from this machine's own counters for the current UTC day — the same numbers the \
             device page shows — so the alert and the page cannot disagree, and it is raised \
             once a day per device rather than per gigabyte."
        }
        "capture_failed" => {
            "Netwatch lost the ability to read packets, so everything it reports is now stale. \
             This is the failure that matters most: a monitor that has silently stopped \
             monitoring. The detail line says what to do about it."
        }
        "test" => "A test alert, written on purpose to prove the delivery path works.",
        _ => "No explanation is recorded for this kind of alert.",
    }
}

/// Append one alert as a single JSON line.
///
/// One line per alert is deliberate: a torn write can lose the alert being
/// written but cannot corrupt the ones already spooled, and a tailing reader
/// never has to parse a half-written record.
pub fn append_alert(path: &std::path::Path, a: &Alert) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{}", a.to_json())
}

pub fn write_test_alert(path: &std::path::Path) -> std::io::Result<()> {
    append_alert(
        path,
        &Alert {
            ts: now_unix(),
            kind: "test",
            severity: "info",
            subject: "netwatchd test alert".into(),
            detail: "If you received this, the alert path works end to end.".into(),
            mac: None,
            name: None,
            address: None,
            muted: false,
        },
    )
}

/// Record an alert in memory and spool it. A failure to write the spool must
/// never take down the caller: the alert is still in memory and in the API.
pub fn emit_alert(
    s: &mut State,
    kind: &'static str,
    severity: &'static str,
    subject: &str,
    detail: &str,
) {
    let a = Alert {
        ts: now_unix(),
        kind,
        severity,
        subject: subject.to_string(),
        detail: detail.to_string(),
        mac: None,
        name: None,
        address: None,
        muted: false,
    };
    push_alert(s, a);
}

/// Record an alert about a specific device.
///
/// A device the operator has marked `ignored` is silent on purpose — that is
/// the whole point of the setting, and it is how a noisy gadget gets muted
/// without weakening the rules for everything else.
pub fn emit_device_alert(
    s: &mut State,
    mac: [u8; 6],
    kind: &'static str,
    severity: &'static str,
    detail: &str,
    extra: &[(&str, &str)],
) {
    let Some(d) = s.devices.get(&mac) else { return };
    if d.trust == crate::devices::Trust::Ignored {
        return;
    }
    // `ignored` means "this is not a device I care about" and drops the alert
    // entirely. A notification rule is the softer thing: the alert is recorded,
    // visible and countable, and simply not sent to the operator's phone.
    let muted = !d.notify.allows(severity);
    let a = Alert {
        ts: now_unix(),
        kind,
        severity,
        subject: crate::devices::mac_string(mac),
        detail: detail.to_string() + &extra_suffix(extra),
        mac: Some(crate::devices::mac_string(mac)),
        name: d.display_name(),
        address: d.primary_ip().map(|ip| ip.to_string()),
        muted,
    };
    push_alert(s, a);
}

/// Fold extra facts into the detail line as `key: value` pairs, so the detail
/// stays one readable line rather than becoming prose.
fn extra_suffix(extra: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (key, value) in extra {
        out.push_str(" · ");
        out.push_str(key);
        out.push_str(": ");
        out.push_str(value);
    }
    out
}

fn push_alert(s: &mut State, a: Alert) {
    if let Some(path) = &s.alert_sink {
        let _ = append_alert(path, &a);
    }
    s.alerts.push_back(a);
    while s.alerts.len() > ALERT_MEMORY {
        s.alerts.pop_front();
    }
}
