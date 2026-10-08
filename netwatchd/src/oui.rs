//! Which maker a hardware address belongs to.
//!
//! The IEEE publishes the assignment registry; `tools/build-oui` trims it into
//! `assets/oui.csv`, which is embedded here. That is public registry data, so a
//! published binary carries no information about any particular network.
//!
//! Parsing happens on first use rather than at startup: the table is ~40 000
//! rows and most runs never look anything up, so nothing pays for it until a
//! device is actually identified.

use std::collections::HashMap;
use std::sync::OnceLock;

const TABLE: &str = include_str!("../assets/oui.csv");

fn table() -> &'static HashMap<&'static str, &'static str> {
    static MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut map = HashMap::new();
        for line in TABLE.lines() {
            if line.starts_with('#') {
                continue;
            }
            if let Some((prefix, vendor)) = line.split_once(',') {
                map.insert(prefix, vendor);
            }
        }
        map
    })
}

/// The maker of the device with this hardware address, if the registry knows it.
///
/// A randomised (locally administered) address is refused without a lookup: by
/// definition it was never assigned by the IEEE, so any match would be a
/// coincidence. Returning `None` there is the honest answer and it keeps the
/// dashboard from confidently naming a phone's throwaway address.
#[must_use]
pub fn vendor_for(mac: [u8; 6]) -> Option<&'static str> {
    if crate::devices::is_randomized(mac) {
        return None;
    }
    let key = format!("{:02X}{:02X}{:02X}", mac[0], mac[1], mac[2]);
    table().get(key.as_str()).copied()
}

/// How many prefixes the embedded table knows. Shown in the dashboard's "how
/// does it know this?" panel so the claim is checkable.
#[must_use]
pub fn table_size() -> usize {
    table().len()
}
