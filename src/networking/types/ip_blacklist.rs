use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;
use prefix_trie::joint::set::JointPrefixSet;

#[derive(Clone, Default, Debug)]
pub struct IpBlacklist {
    ips: Arc<HashSet<IpAddr>>,
    cidrs: Arc<JointPrefixSet<IpNet>>,
    is_loading: bool,
}

impl IpBlacklist {
    pub async fn from_file(path: String) -> Self {
        let Ok(buf) = tokio::fs::read_to_string(&path).await else {
            return IpBlacklist::default();
        };
        let mut ips = HashSet::new();
        let mut cidrs = JointPrefixSet::new();
        for line in buf.lines() {
            let Some(first) = line.split_whitespace().next() else {
                continue;
            };

            if let Ok(ip) = first.parse::<IpAddr>() {
                ips.insert(ip);
            } else if let Ok(cidr) = first.parse::<IpNet>() {
                cidrs.insert(cidr);
            }
        }
        IpBlacklist {
            ips: Arc::new(ips),
            cidrs: Arc::new(cidrs),
            is_loading: false,
        }
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.ips.contains(ip) || self.cidrs.get_lpm(&IpNet::from(*ip)).is_some()
    }

    pub fn is_invalid(&self) -> bool {
        self.ips.is_empty() && self.cidrs.is_empty() && !self.is_loading
    }

    pub fn is_loading(&self) -> bool {
        self.is_loading
    }

    pub fn imported_items_info(&self) -> Option<String> {
        match (self.ips.len(), self.cidrs.len()) {
            (0, 0) => None,
            (ips, 0) => Some(format!("(IPs: {ips})")),
            (0, cidrs) => Some(format!("(CIDRs: {cidrs})")),
            (ips, cidrs) => Some(format!("(IPs: {ips}, CIDRs: {cidrs})")),
        }
    }

    pub fn start_loading(&mut self) {
        self.is_loading = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_ip_blacklist_valid() {
        let blacklist =
            IpBlacklist::from_file("resources/test/ip_blacklist_valid.txt".to_string()).await;

        assert!(!blacklist.is_invalid());
        assert!(!blacklist.is_loading());
        assert_eq!(blacklist.ips.len(), 4);
        assert_eq!(blacklist.cidrs.len(), 0);
        assert_eq!(
            blacklist.imported_items_info(),
            Some("(IPs: 4)".to_string())
        );

        assert!(blacklist.contains(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(blacklist.contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 255))));
        assert!(blacklist.contains(&"::123".parse::<IpAddr>().unwrap()));
        assert!(blacklist.contains(&"fe80::99".parse::<IpAddr>().unwrap()));

        assert!(!blacklist.contains(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 9))));
        assert!(!blacklist.contains(&IpAddr::V4(Ipv4Addr::new(10, 2, 3, 255))));
        assert!(!blacklist.contains(&"::124".parse::<IpAddr>().unwrap()));
        assert!(!blacklist.contains(&"fe80::98".parse::<IpAddr>().unwrap()));
    }

    #[tokio::test]
    async fn test_ip_blacklist_invalid() {
        let blacklist =
            IpBlacklist::from_file("resources/test/ip_blacklist_invalid.txt".to_string()).await;

        assert!(blacklist.is_invalid());
        assert!(!blacklist.is_loading());
        assert_eq!(blacklist.ips.len(), 0);
        assert_eq!(blacklist.cidrs.len(), 0);
        assert_eq!(blacklist.imported_items_info(), None);

        assert!(!blacklist.contains(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!blacklist.contains(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
        assert!(!blacklist.contains(&"::123".parse::<IpAddr>().unwrap()));
        assert!(!blacklist.contains(&"::".parse::<IpAddr>().unwrap()));
    }

    #[tokio::test]
    async fn test_ip_blacklist_valid_with_cidr() {
        let blacklist =
            IpBlacklist::from_file("resources/test/ip_blacklist_valid_with_cidr.txt".to_string())
                .await;

        assert!(!blacklist.is_invalid());
        assert!(!blacklist.is_loading());
        assert_eq!(blacklist.ips.len(), 2);
        assert_eq!(blacklist.cidrs.len(), 4);
        assert_eq!(
            blacklist.imported_items_info(),
            Some("(IPs: 2, CIDRs: 4)".to_string())
        );

        assert!(blacklist.contains(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(blacklist.contains(&"2001:db8::1".parse::<IpAddr>().unwrap()));
        assert!(!blacklist.contains(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 9))));
        assert!(!blacklist.contains(&"2001:db8::2".parse::<IpAddr>().unwrap()));

        assert!(blacklist.contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 1))));
        assert!(blacklist.contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 255))));
        assert!(!blacklist.contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 5, 1))));

        assert!(blacklist.contains(&"2001:db9::1".parse::<IpAddr>().unwrap()));
        assert!(blacklist.contains(&"2001:db9:ffff::1".parse::<IpAddr>().unwrap()));
        assert!(!blacklist.contains(&"2001:dba::1".parse::<IpAddr>().unwrap()));

        assert!(blacklist.contains(&IpAddr::V4(Ipv4Addr::new(5, 6, 7, 10))));
        assert!(!blacklist.contains(&IpAddr::V4(Ipv4Addr::new(5, 6, 8, 10))));

        assert!(blacklist.contains(&IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))));
        assert!(!blacklist.contains(&IpAddr::V4(Ipv4Addr::new(9, 9, 10, 9))));
    }

    #[tokio::test]
    async fn test_ip_blacklist_valid_with_cidr_only() {
        let blacklist =
            IpBlacklist::from_file("resources/test/ip_blacklist_valid_cidr_only.txt".to_string())
                .await;

        assert!(!blacklist.is_invalid());
        assert!(!blacklist.is_loading());
        assert_eq!(blacklist.ips.len(), 0);
        assert_eq!(blacklist.cidrs.len(), 1);
        assert_eq!(
            blacklist.imported_items_info(),
            Some("(CIDRs: 1)".to_string())
        );

        assert!(blacklist.contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 1))));
        assert!(!blacklist.contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 4, 1))));
    }

    #[tokio::test]
    async fn test_ip_blacklist_real_cidr_ranges() {
        let blacklist =
            IpBlacklist::from_file("resources/test/ip_blacklist_real_cidr_ranges.txt".to_string())
                .await;

        assert!(!blacklist.is_invalid());
        assert_eq!(blacklist.ips.len(), 0);
        assert_eq!(blacklist.cidrs.len(), 6);
        assert_eq!(
            blacklist.imported_items_info(),
            Some("(CIDRs: 6)".to_string())
        );

        assert!(blacklist.contains(&IpAddr::V4(Ipv4Addr::new(209, 186, 20, 0))));
        assert!(blacklist.contains(&IpAddr::V4(Ipv4Addr::new(209, 186, 23, 255))));
        assert!(blacklist.contains(&IpAddr::V4(Ipv4Addr::new(209, 186, 24, 0))));
        assert!(blacklist.contains(&IpAddr::V4(Ipv4Addr::new(209, 186, 31, 255))));
        assert!(blacklist.contains(&IpAddr::V4(Ipv4Addr::new(209, 186, 224, 0))));
        assert!(blacklist.contains(&IpAddr::V4(Ipv4Addr::new(209, 186, 231, 255))));
        assert!(blacklist.contains(&IpAddr::V4(Ipv4Addr::new(209, 186, 232, 0))));
        assert!(blacklist.contains(&IpAddr::V4(Ipv4Addr::new(209, 186, 235, 255))));
        assert!(blacklist.contains(&IpAddr::V4(Ipv4Addr::new(209, 186, 236, 0))));
        assert!(blacklist.contains(&IpAddr::V4(Ipv4Addr::new(209, 186, 236, 255))));
        assert!(blacklist.contains(&IpAddr::V4(Ipv4Addr::new(209, 233, 156, 0))));
        assert!(blacklist.contains(&IpAddr::V4(Ipv4Addr::new(209, 233, 159, 255))));

        assert!(!blacklist.contains(&IpAddr::V4(Ipv4Addr::new(209, 186, 19, 255))));
        assert!(!blacklist.contains(&IpAddr::V4(Ipv4Addr::new(209, 186, 32, 0))));
        assert!(!blacklist.contains(&IpAddr::V4(Ipv4Addr::new(209, 186, 237, 0))));
        assert!(!blacklist.contains(&IpAddr::V4(Ipv4Addr::new(209, 233, 160, 0))));
    }
}
