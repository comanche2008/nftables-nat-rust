use nat_common::IpVersion;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::{LazyLock, Mutex};

type CacheKey = (String, IpVersion);

static LAST_GOOD_IP: LazyLock<Mutex<HashMap<CacheKey, IpAddr>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 统一的IP地址解析函数，支持IPv4、IPv6和Both模式。
/// 若上次选用的地址仍在解析结果中，则保持不变，避免 DNS round-robin 导致规则抖动。
pub fn remote_ip(domain: &str, ip_version: &IpVersion) -> io::Result<String> {
    if let Ok(ip) = domain.parse::<IpAddr>() {
        return match ip_version {
            IpVersion::V4 if ip.is_ipv4() => Ok(ip.to_string()),
            IpVersion::V6 if ip.is_ipv6() => Ok(ip.to_string()),
            IpVersion::All => Ok(ip.to_string()),
            IpVersion::V4 => Err(io::Error::other(
                "Domain resolved to IPv6 but IPv4 was requested",
            )),
            IpVersion::V6 => Err(io::Error::other(
                "Domain resolved to IPv4 but IPv6 was requested",
            )),
        };
    }

    let socket_addrs: Vec<_> = (domain, 80u16).to_socket_addrs()?.collect();
    let ips: Vec<IpAddr> = socket_addrs.iter().map(|addr| addr.ip()).collect();

    let candidates: Vec<IpAddr> = match ip_version {
        IpVersion::V4 => ips.into_iter().filter(IpAddr::is_ipv4).collect(),
        IpVersion::V6 => ips.into_iter().filter(IpAddr::is_ipv6).collect(),
        IpVersion::All => {
            let v4: Vec<IpAddr> = ips.iter().copied().filter(IpAddr::is_ipv4).collect();
            if v4.is_empty() {
                ips.into_iter().filter(IpAddr::is_ipv6).collect()
            } else {
                v4
            }
        }
    };

    if candidates.is_empty() {
        return Err(io::Error::other(match ip_version {
            IpVersion::V4 => "Failed to resolve IPv4 address",
            IpVersion::V6 => "Failed to resolve IPv6 address",
            IpVersion::All => "Failed to resolve any IP address",
        }));
    }

    let key = (domain.to_string(), *ip_version);
    let mut cache = LAST_GOOD_IP.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(previous) = cache.get(&key)
        && candidates.contains(previous)
    {
        return Ok(previous.to_string());
    }

    let chosen = candidates
        .iter()
        .min_by_key(|ip| ip.to_string())
        .copied()
        .ok_or_else(|| io::Error::other("Failed to select IP address"))?;
    cache.insert(key, chosen);
    Ok(chosen.to_string())
}

#[allow(clippy::unwrap_used)]
mod test {
    #[test]
    fn test_remote_ip_literal_v4() {
        use nat_common::IpVersion;
        let ip = super::remote_ip("1.2.3.4", &IpVersion::All).unwrap();
        assert_eq!(ip, "1.2.3.4");
    }

    #[test]
    fn test_remote_ip_v4() {
        use nat_common::IpVersion;
        use std::net::Ipv4Addr;
        let domain = "www.google.com";
        let ip = super::remote_ip(domain, &IpVersion::V4).unwrap();
        println!("Resolved IPv4 for {domain}: {ip}");
        assert!(!ip.is_empty());
        assert!(ip.parse::<Ipv4Addr>().is_ok());
    }

    #[test]
    fn test_remote_ip_both() {
        use nat_common::IpVersion;
        let domain = "www.google.com";
        let ip = super::remote_ip(domain, &IpVersion::All).unwrap();
        println!("Resolved IP (Both mode) for {domain}: {ip}");
        assert!(!ip.is_empty());
        assert!(ip.parse::<std::net::IpAddr>().is_ok());
    }

    #[test]
    fn test_resolve_localhost() {
        use nat_common::IpVersion;
        let domain = "localhost";
        let ip = super::remote_ip(domain, &IpVersion::All).unwrap();
        println!("Resolved IP (Both mode) for {domain}: {ip}");
        assert!(!ip.is_empty());
        assert!(ip.parse::<std::net::IpAddr>().is_ok());

        let ip = super::remote_ip(domain, &IpVersion::V6).unwrap();
        println!("Resolved IP (V6) for {domain}: {ip}");
        assert!(!ip.is_empty());
        assert!(ip.parse::<std::net::IpAddr>().is_ok());
    }

    #[test]
    fn test_remote_ip_fail() {
        use nat_common::IpVersion;
        let domain = "example.asddddddddddddddddddddaasdasdasdasdasdasadasads.com";
        let res = super::remote_ip(domain, &IpVersion::V4);
        println!("Resolved IPv4 for {domain}: {res:?}");
        assert!(res.is_err());
    }

    #[test]
    fn test_remote_ip_prefers_cached_address() {
        use nat_common::IpVersion;
        let domain = "www.google.com";
        let first = super::remote_ip(domain, &IpVersion::V4).unwrap();
        let second = super::remote_ip(domain, &IpVersion::V4).unwrap();
        assert_eq!(first, second);
    }
}
