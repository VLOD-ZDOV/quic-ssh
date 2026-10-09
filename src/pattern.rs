//! OpenSSH-style patterns: `*` and `?` wildcards, comma lists with `!` negation,
//! and CIDR address lists.

use std::net::IpAddr;

/// Shell-style match of `text` against `pattern` (`*` = any run, `?` = one char).
pub fn wildcard(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti, mut star, mut mark) = (0, 0, None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// A pattern list matches if any positive pattern matches and no negated one
/// does (case-insensitive, like host names in ssh_config and known_hosts).
pub fn host_matches<S: AsRef<str>>(patterns: &[S], host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let mut matched = false;
    for p in patterns {
        let p = p.as_ref().to_ascii_lowercase();
        if let Some(neg) = p.strip_prefix('!') {
            if wildcard(neg, &host) {
                return false;
            }
        } else if wildcard(&p, &host) {
            matched = true;
        }
    }
    matched
}

/// Like [`host_matches`], but case-sensitive (user and group names).
pub fn name_matches<S: AsRef<str>>(patterns: &[S], name: &str) -> bool {
    let mut matched = false;
    for p in patterns {
        let p = p.as_ref();
        if let Some(neg) = p.strip_prefix('!') {
            if wildcard(neg, name) {
                return false;
            }
        } else if wildcard(p, name) {
            matched = true;
        }
    }
    matched
}

/// `host:port`, `[v6]:port` or (for listeners) just `port`; `*` matches any port or host.
pub fn endpoint_matches(pattern: &str, host: &str, port: u16, listen: bool) -> bool {
    let (p_host, p_port) = match pattern.rsplit_once(':') {
        Some((h, p)) => (h.trim_start_matches('[').trim_end_matches(']'), p),
        None if listen => ("", pattern),
        None => return false,
    };
    let port_ok = p_port == "*" || p_port.parse::<u16>().ok() == Some(port);
    let host_ok = p_host == "*" || p_host.eq_ignore_ascii_case(host) || (listen && p_host.is_empty() && matches!(host, "" | "localhost"));
    port_ok && host_ok
}

/// Whether `ip` is inside `cidr` (`192.0.2.0/24`, `2001:db8::/32`, or a plain address).
pub fn cidr_contains(cidr: &str, ip: IpAddr) -> Option<bool> {
    let (addr, bits) = match cidr.split_once('/') {
        Some((a, b)) => (a, Some(b.parse::<u8>().ok()?)),
        None => (cidr, None),
    };
    let net: IpAddr = addr.parse().ok()?;
    let ip = ip.to_canonical();
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            let bits = bits.unwrap_or(32);
            if bits > 32 {
                return None;
            }
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            Some(u32::from(n) & mask == u32::from(i) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            let bits = bits.unwrap_or(128);
            if bits > 128 {
                return None;
            }
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            Some(u128::from(n) & mask == u128::from(i) & mask)
        }
        _ => Some(false),
    }
}

/// `from=` in authorized_keys: comma-separated address patterns (wildcards or
/// CIDR, `!` to exclude). Like sshd, a negated match denies, then any positive
/// match allows. Host name patterns cannot match, since qshd does no reverse DNS.
/// A malformed CIDR denies, as in sshd (a typo must not open an exclusion).
pub fn address_allowed(list: &str, ip: IpAddr) -> bool {
    let text = ip.to_canonical().to_string();
    let mut allowed = false;
    for p in list.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (neg, p) = match p.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, p),
        };
        let hit = if p.contains('/') {
            match cidr_contains(p, ip) {
                Some(hit) => hit,
                None => return false,
            }
        } else {
            wildcard(p, &text)
        };
        if hit && neg {
            return false;
        }
        allowed |= hit;
    }
    allowed
}

/// A certificate's `source-address`: comma-separated CIDR list; any malformed entry denies.
pub fn source_address_allowed(list: &str, ip: IpAddr) -> bool {
    let mut allowed = false;
    for c in list.split(',').map(str::trim) {
        match cidr_contains(c, ip) {
            Some(hit) => allowed |= hit,
            None => return false,
        }
    }
    allowed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards() {
        assert!(wildcard("*", "anything"));
        assert!(wildcard("web-?.example.com", "web-1.example.com"));
        assert!(!wildcard("web-?.example.com", "web-10.example.com"));
        assert!(wildcard("*.example.com", "a.b.example.com"));
        assert!(!wildcard("*.example.com", "example.com"));
    }

    #[test]
    fn addresses() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(address_allowed("192.0.2.*", ip("192.0.2.7")));
        assert!(address_allowed("10.0.0.0/8,192.0.2.0/24", ip("192.0.2.7")));
        assert!(!address_allowed("192.0.2.0/24,!192.0.2.7", ip("192.0.2.7")));
        assert!(!address_allowed("!192.0.2.7", ip("198.51.100.1")), "only negations never allow");
        assert!(address_allowed("2001:db8::/32", ip("2001:db8::1")));
        assert!(address_allowed("127.0.0.1", ip("::ffff:127.0.0.1")), "mapped addresses count as IPv4");
        assert!(!address_allowed("example.com", ip("192.0.2.7")));
        assert!(!address_allowed("!10.0.0.0/33,*", ip("10.0.0.1")), "a malformed exclusion denies");
        assert!(source_address_allowed("192.0.2.0/24", ip("192.0.2.9")));
        assert!(!source_address_allowed("192.0.2.0/24,bogus", ip("192.0.2.9")));
        assert!(!source_address_allowed("192.0.2.0/33", ip("192.0.2.9")));
    }
}
