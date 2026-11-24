use std::net::{IpAddr, ToSocketAddrs};

use ipnet::IpNet;
use url::Url;

use crate::config::NetworkPolicy;
use crate::error::{GuardError, Result};

/// Validates URLs and domains against allowlists, denylists, and SSRF IP ranges.
#[derive(Debug, Clone)]
pub struct NetworkValidator {
    allowed_domains: Vec<String>,
    denied_domains: Vec<String>,
    block_private_ips: bool,
    resolve_dns: bool,
    private_nets: Vec<IpNet>,
}

impl NetworkValidator {
    /// Build a `NetworkValidator` from a `NetworkPolicy`.
    pub fn new(policy: &NetworkPolicy) -> Self {
        let private_cidrs = [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "0.0.0.0/8",
            "100.64.0.0/10",
            "224.0.0.0/4",
            "::/128",
            "::1/128",
            "fc00::/7",
            "fe80::/10",
            "ff00::/8",
        ];
        let private_nets = private_cidrs
            .iter()
            .filter_map(|s| s.parse::<IpNet>().ok())
            .collect();

        Self {
            allowed_domains: policy
                .allowed_domains
                .iter()
                .map(|d| d.to_ascii_lowercase())
                .collect(),
            denied_domains: policy
                .denied_domains
                .iter()
                .map(|d| d.to_ascii_lowercase())
                .collect(),
            block_private_ips: policy.block_private_ips,
            resolve_dns: policy.resolve_dns,
            private_nets,
        }
    }

    /// Validate an HTTP/HTTPS/WS URL string.
    pub fn check_url(&self, raw: &str) -> Result<()> {
        let parsed = Url::parse(raw)
            .map_err(|e| GuardError::PolicyDenied(format!("invalid URL '{raw}': {e}")))?;

        let scheme = parsed.scheme();
        if !matches!(scheme, "http" | "https" | "ws" | "wss") {
            return Err(GuardError::PolicyDenied(format!(
                "URL scheme '{scheme}' is not permitted"
            )));
        }

        let host = parsed
            .host_str()
            .ok_or_else(|| GuardError::PolicyDenied(format!("URL '{raw}' has no host")))?;
        let host_lower = host.trim_matches(['[', ']']).to_ascii_lowercase();

        if self.block_private_ips {
            if is_private_hostname(&host_lower) {
                return Err(GuardError::PolicyDenied(format!(
                    "SSRF protection blocked private/metadata host '{host_lower}'"
                )));
            }
            if let Ok(ip) = host_lower.parse::<IpAddr>() {
                if self.is_private_ip(ip) {
                    return Err(GuardError::PolicyDenied(format!(
                        "SSRF protection blocked private/metadata IP '{ip}'"
                    )));
                }
            } else if self.resolve_dns {
                let port = parsed.port_or_known_default().unwrap_or(80);
                if let Ok(addrs) = (host_lower.as_str(), port).to_socket_addrs() {
                    for addr in addrs {
                        if self.is_private_ip(addr.ip()) {
                            return Err(GuardError::PolicyDenied(format!(
                                "SSRF protection blocked '{host_lower}' resolving to private IP '{}'",
                                addr.ip()
                            )));
                        }
                    }
                }
            }
        }

        if self
            .denied_domains
            .iter()
            .any(|pat| domain_matches(&host_lower, pat))
        {
            return Err(GuardError::PolicyDenied(format!(
                "domain '{host_lower}' is explicitly denied"
            )));
        }

        if !self.allowed_domains.is_empty()
            && !self
                .allowed_domains
                .iter()
                .any(|pat| domain_matches(&host_lower, pat))
        {
            return Err(GuardError::PolicyDenied(format!(
                "domain '{host_lower}' is not in allowed_domains"
            )));
        }

        Ok(())
    }

    fn is_private_ip(&self, ip: IpAddr) -> bool {
        if let IpAddr::V6(v6) = ip {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return self.is_private_ip(IpAddr::V4(v4));
            }
        }
        ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_multicast()
            || self.private_nets.iter().any(|net| net.contains(&ip))
    }
}

fn is_private_hostname(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host == "metadata.google.internal"
}

fn domain_matches(host: &str, pattern: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix || host.ends_with(&format!(".{suffix}"))
    } else {
        host == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_ssrf_and_enforces_domain_allowlist() {
        let policy = NetworkPolicy {
            allowed_domains: vec!["api.github.com".into(), "*.docs.rs".into()],
            denied_domains: vec!["evil.docs.rs".into()],
            block_private_ips: true,
            ..Default::default()
        };
        let v = NetworkValidator::new(&policy);

        assert!(v.check_url("http://127.0.0.1:8080/admin").is_err());
        assert!(v
            .check_url("http://169.254.169.254/latest/meta-data")
            .is_err());
        assert!(v.check_url("http://10.0.0.5/internal").is_err());
        assert!(v.check_url("http://[::1]:3000/").is_err());
        assert!(v.check_url("http://localhost:9000").is_err());
        assert!(v.check_url("https://evil.docs.rs/foo").is_err());
        assert!(v.check_url("https://example.com/").is_err());

        assert!(v.check_url("https://api.github.com/repos").is_ok());
        assert!(v.check_url("https://crates.docs.rs/tokio").is_ok());
    }
}
