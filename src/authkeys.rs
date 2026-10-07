//! authorized_keys entries with options (as in sshd(8), "AUTHORIZED_KEYS FILE
//! FORMAT"), user certificates, and the restrictions they put on a login.
//!
//! Unknown options make the whole line unusable: a restriction qshd cannot
//! enforce must never turn into unrestricted access.

use std::net::IpAddr;

use anyhow::{bail, Context, Result};
use ssh_key::certificate::CertType;
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, Certificate, HashAlg};

use crate::pattern::{address_allowed, source_address_allowed};

/// What a logged-in session may do.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Restrictions {
    /// Forced command (`command=`, or a certificate's `force-command`).
    pub command: Option<String>,
    pub no_pty: bool,
    pub no_port_forwarding: bool,
    pub no_agent_forwarding: bool,
    /// `permitopen="host:port"`: allowed `-L`/`-D`/`-W` destinations (empty = any).
    pub permit_open: Vec<String>,
    /// `permitlisten="[host:]port"`: allowed `-R` listeners (empty = any).
    pub permit_listen: Vec<String>,
}

impl Restrictions {
    /// Whether `-L`/`-D`/`-W` may connect to `host:port`.
    pub fn may_open(&self, host: &str, port: u16) -> bool {
        !self.no_port_forwarding && (self.permit_open.is_empty() || self.permit_open.iter().any(|p| endpoint_matches(p, host, port, false)))
    }

    /// Whether `-R` may listen on `bind:port` (`bind` empty = default address).
    pub fn may_listen(&self, bind: &str, port: u16) -> bool {
        !self.no_port_forwarding
            && (self.permit_listen.is_empty() || self.permit_listen.iter().any(|p| endpoint_matches(p, bind, port, true)))
    }
}

/// `host:port`, `[v6]:port` or (for listeners) just `port`; `*` matches any port or host.
fn endpoint_matches(pattern: &str, host: &str, port: u16, listen: bool) -> bool {
    let (p_host, p_port) = match pattern.rsplit_once(':') {
        Some((h, p)) => (h.trim_start_matches('[').trim_end_matches(']'), p),
        None if listen => ("", pattern),
        None => return false,
    };
    let port_ok = p_port == "*" || p_port.parse::<u16>().ok() == Some(port);
    let host_ok = p_host == "*" || p_host.eq_ignore_ascii_case(host) || (listen && p_host.is_empty() && matches!(host, "" | "localhost"));
    port_ok && host_ok
}

/// One usable authorized_keys line.
#[derive(Clone, Debug)]
pub struct AuthorizedKey {
    pub key: KeyData,
    pub restrictions: Restrictions,
    /// `from=`: client addresses allowed to use the key.
    pub from: Option<String>,
    /// `expiry-time=`, as Unix time.
    pub expiry: Option<u64>,
    /// `cert-authority`: the key signs user certificates instead of logging in.
    pub cert_authority: bool,
    /// `principals=` for `cert-authority` lines.
    pub principals: Option<Vec<String>>,
    /// Security keys: user presence is not needed (`no-touch-required`).
    pub no_touch_required: bool,
    /// Security keys: user verification (PIN or biometrics) is needed.
    pub verify_required: bool,
}

const KEY_TYPES: [&str; 6] = [
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-dss",
];

/// Splits the options field at the first unquoted whitespace.
fn split_options(line: &str) -> Result<(&str, &str)> {
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => return Ok((&line[..i], line[i..].trim_start())),
            _ => {}
        }
    }
    bail!("no key after the options")
}

/// `name` or `name="value"` options, separated by unquoted commas.
fn parse_options(text: &str) -> Result<Vec<(String, Option<String>)>> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    loop {
        let mut name = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c == ',' {
                break;
            }
            name.push(c);
            chars.next();
        }
        if name.is_empty() {
            bail!("empty option");
        }
        let value = if chars.peek() == Some(&'=') {
            chars.next();
            if chars.next() != Some('"') {
                bail!("value of option {name} must be quoted");
            }
            let mut v = String::new();
            loop {
                match chars.next() {
                    Some('\\') if chars.peek() == Some(&'"') => v.push(chars.next().unwrap()),
                    Some('"') => break,
                    Some(c) => v.push(c),
                    None => bail!("unterminated value of option {name}"),
                }
            }
            Some(v)
        } else {
            None
        };
        out.push((name.to_ascii_lowercase(), value));
        match chars.next() {
            None => return Ok(out),
            Some(',') => {}
            Some(c) => bail!("unexpected {c:?} after option"),
        }
    }
}

/// `YYYYMMDD[HHMM[SS]]` in local time, or UTC with a trailing `Z`.
fn parse_expiry(v: &str) -> Result<u64> {
    let (digits, utc) = match v.strip_suffix(['Z', 'z']) {
        Some(d) => (d, true),
        None => (v, false),
    };
    if !matches!(digits.len(), 8 | 12 | 14) || !digits.bytes().all(|b| b.is_ascii_digit()) {
        bail!("bad expiry-time {v:?}");
    }
    let n = |r: std::ops::Range<usize>| digits.get(r).map(|s| s.parse::<i32>().unwrap()).unwrap_or(0);
    // SAFETY: `tm` is fully initialised (zeroed, then set) and only read by libc.
    let t = unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        tm.tm_year = n(0..4) - 1900;
        tm.tm_mon = n(4..6) - 1;
        tm.tm_mday = n(6..8);
        tm.tm_hour = n(8..10);
        tm.tm_min = n(10..12);
        tm.tm_sec = n(12..14);
        tm.tm_isdst = -1;
        if utc { libc::timegm(&mut tm) } else { libc::mktime(&mut tm) }
    };
    u64::try_from(t).context("bad expiry-time")
}

/// Parses one authorized_keys line. `Ok(None)` for blank lines and comments;
/// an error for lines that must not be used (bad syntax, unknown options).
pub fn parse_line(line: &str) -> Result<Option<AuthorizedKey>> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let (options, key_text) = if KEY_TYPES.iter().any(|t| line.starts_with(t)) {
        ("", line)
    } else {
        split_options(line)?
    };
    let key = ssh_key::PublicKey::from_openssh(key_text).context("cannot parse key")?;
    let mut entry = AuthorizedKey {
        key: key.key_data().clone(),
        restrictions: Restrictions::default(),
        from: None,
        expiry: None,
        cert_authority: false,
        principals: None,
        no_touch_required: false,
        verify_required: false,
    };
    if options.is_empty() {
        return Ok(Some(entry));
    }
    let r = &mut entry.restrictions;
    for (name, value) in parse_options(options)? {
        let need = |v: Option<String>| v.with_context(|| format!("option {name} needs a value"));
        match name.as_str() {
            "command" => r.command = Some(need(value)?),
            "from" => entry.from = Some(need(value)?),
            "permitopen" => r.permit_open.push(need(value)?),
            "permitlisten" => r.permit_listen.push(need(value)?),
            "expiry-time" => entry.expiry = Some(parse_expiry(&need(value)?)?),
            "principals" => entry.principals = Some(need(value)?.split(',').map(|s| s.trim().to_string()).collect()),
            "cert-authority" => entry.cert_authority = true,
            "restrict" => {
                r.no_pty = true;
                r.no_port_forwarding = true;
                r.no_agent_forwarding = true;
            }
            "no-pty" => r.no_pty = true,
            "pty" => r.no_pty = false,
            "no-port-forwarding" => r.no_port_forwarding = true,
            "port-forwarding" => r.no_port_forwarding = false,
            "no-agent-forwarding" => r.no_agent_forwarding = true,
            "agent-forwarding" => r.no_agent_forwarding = false,
            "no-touch-required" => entry.no_touch_required = true,
            "verify-required" => entry.verify_required = true,
            // qsh has no X11 forwarding, user rc files or tunnels: nothing to allow or deny.
            "no-x11-forwarding" | "x11-forwarding" | "no-user-rc" | "user-rc" => {}
            // Like sshd with PermitUserEnvironment off: ignored.
            "environment" => {}
            other => bail!("unsupported option {other:?}"),
        }
    }
    Ok(Some(entry))
}

/// Parses an authorized_keys text. Unusable lines are reported through `skip`.
pub fn parse_list(text: &str, mut skip: impl FnMut(usize, anyhow::Error)) -> Vec<AuthorizedKey> {
    text.lines()
        .enumerate()
        .filter_map(|(i, l)| parse_line(l).unwrap_or_else(|e| {
            skip(i + 1, e);
            None
        }))
        .collect()
}

/// A key or certificate offered by a client.
#[derive(Clone, Debug)]
pub enum Offered {
    Key(KeyData),
    Cert(Box<Certificate>),
}

impl Offered {
    /// Parses an SSH wire-format public key or certificate.
    pub fn from_bytes(bytes: &[u8]) -> Result<Offered> {
        match ssh_key::PublicKey::from_bytes(bytes) {
            Ok(k) => Ok(Offered::Key(k.key_data().clone())),
            Err(_) => Ok(Offered::Cert(Box::new(Certificate::from_bytes(bytes).context("unknown key format")?))),
        }
    }

    /// The key that signs for this login.
    pub fn signing_key(&self) -> &KeyData {
        match self {
            Offered::Key(k) => k,
            Offered::Cert(c) => c.public_key(),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Offered::Key(k) => format!("{} {}", k.algorithm(), k.fingerprint(HashAlg::Sha256)),
            Offered::Cert(c) => format!(
                "certificate {:?} serial {} for {} signed by CA {}",
                c.key_id(),
                c.serial(),
                c.public_key().fingerprint(HashAlg::Sha256),
                c.signature_key().fingerprint(HashAlg::Sha256)
            ),
        }
    }
}

/// The outcome of a successful key check.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Grant {
    pub restrictions: Restrictions,
    /// For security keys: the signature must have the user-presence flag.
    pub require_presence: bool,
    /// For security keys: the signature must have the user-verified flag.
    pub require_verified: bool,
}

/// Who is logging in from where, and when.
pub struct Login<'a> {
    pub user: &'a str,
    pub ip: IpAddr,
    pub now: u64,
}

fn is_security_key(k: &KeyData) -> bool {
    matches!(k.algorithm(), Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256)
}

fn entry_usable(e: &AuthorizedKey, login: &Login) -> Result<(), String> {
    if e.expiry.is_some_and(|t| login.now >= t) {
        return Err("key has expired (expiry-time)".into());
    }
    if let Some(from) = &e.from {
        if !address_allowed(from, login.ip) {
            return Err(format!("{} is not allowed by from=\"{from}\"", login.ip));
        }
    }
    Ok(())
}

/// Checks an offered key or certificate against the user's authorized_keys
/// entries and the server's trusted user CAs. On failure, returns the reason
/// for the log (the client only ever learns "denied").
pub fn check(offered: &Offered, entries: &[AuthorizedKey], trusted_cas: &[KeyData], login: &Login) -> Result<Grant, String> {
    match offered {
        Offered::Key(key) => {
            let mut reason = "key is not in authorized_keys".to_string();
            for e in entries.iter().filter(|e| !e.cert_authority && &e.key == key) {
                match entry_usable(e, login) {
                    Ok(()) => {
                        return Ok(Grant {
                            restrictions: e.restrictions.clone(),
                            require_presence: is_security_key(key) && !e.no_touch_required,
                            require_verified: e.verify_required,
                        });
                    }
                    Err(r) => reason = r,
                }
            }
            Err(reason)
        }
        Offered::Cert(cert) => check_cert(cert, entries, trusted_cas, login),
    }
}

fn check_cert(cert: &Certificate, entries: &[AuthorizedKey], trusted_cas: &[KeyData], login: &Login) -> Result<Grant, String> {
    if cert.cert_type() != CertType::User {
        return Err("not a user certificate".into());
    }
    let ca = cert.signature_key();
    let principals = cert.valid_principals();
    // Either the server trusts the CA for everyone (principal = user name), or
    // the user trusts it in authorized_keys (principals= or the user name).
    let mut grant = None;
    if trusted_cas.contains(ca) {
        if !principals.iter().any(|p| p == login.user) {
            return Err(format!("certificate is not valid for {}", login.user));
        }
        grant = Some(Grant::default());
    } else {
        let mut reason = "certificate authority is not trusted".to_string();
        for e in entries.iter().filter(|e| e.cert_authority && &e.key == ca) {
            if let Err(r) = entry_usable(e, login) {
                reason = r;
                continue;
            }
            let ok = match &e.principals {
                Some(allowed) => principals.iter().any(|p| allowed.contains(p)),
                None => principals.iter().any(|p| p == login.user),
            };
            if !ok {
                reason = format!("certificate principals {principals:?} not allowed for {}", login.user);
                continue;
            }
            grant = Some(Grant { restrictions: e.restrictions.clone(), require_presence: false, require_verified: e.verify_required });
            break;
        }
        if grant.is_none() {
            return Err(reason);
        }
    }
    let mut grant = grant.unwrap();
    let fp = ca.fingerprint(HashAlg::Sha256);
    cert.validate_at(login.now, [&fp]).map_err(|_| "certificate signature or validity period is wrong".to_string())?;

    let r = &mut grant.restrictions;
    for (name, value) in cert.critical_options().iter() {
        match name.as_str() {
            "force-command" => match &r.command {
                Some(c) if c != value => return Err("certificate force-command conflicts with command=".into()),
                _ => r.command = Some(value.clone()),
            },
            "source-address" => {
                if !source_address_allowed(value, login.ip) {
                    return Err(format!("{} is not allowed by the certificate's source-address", login.ip));
                }
            }
            "verify-required" => grant.require_verified = true,
            other => return Err(format!("unsupported critical option {other:?}")),
        }
    }
    let ext = cert.extensions();
    r.no_pty |= !ext.contains_key("permit-pty");
    r.no_port_forwarding |= !ext.contains_key("permit-port-forwarding");
    r.no_agent_forwarding |= !ext.contains_key("permit-agent-forwarding");
    grant.require_presence = is_security_key(cert.public_key()) && !ext.contains_key("no-touch-required");
    Ok(grant)
}

/// Security-key signatures end with a flags byte and a 4-byte counter.
pub fn security_key_flags(signature: &ssh_key::Signature) -> Option<u8> {
    let data = signature.as_bytes();
    matches!(signature.algorithm(), Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256)
        .then(|| data.len().checked_sub(5).map(|i| data[i]))
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test";

    #[test]
    fn options_are_parsed() {
        let e = parse_line(&format!(r#"command="echo \"hi\", there",from="192.0.2.0/24,!192.0.2.9",no-pty,permitopen="db:5432",permitopen="*:80" {KEY}"#))
            .unwrap()
            .unwrap();
        assert_eq!(e.restrictions.command.as_deref(), Some(r#"echo "hi", there"#));
        assert_eq!(e.from.as_deref(), Some("192.0.2.0/24,!192.0.2.9"));
        assert!(e.restrictions.no_pty && !e.restrictions.no_port_forwarding);
        assert!(e.restrictions.may_open("db", 5432) && e.restrictions.may_open("web", 80));
        assert!(!e.restrictions.may_open("db", 22));
        let e = parse_line(&format!("restrict,pty,permitlisten=\"8080\" {KEY}")).unwrap().unwrap();
        assert!(!e.restrictions.no_pty && e.restrictions.no_port_forwarding && e.restrictions.no_agent_forwarding);
        assert!(parse_line(KEY).unwrap().unwrap().restrictions == Restrictions::default());
        assert!(parse_line("# comment").unwrap().is_none());
    }

    #[test]
    fn unknown_or_broken_options_disable_the_line() {
        for bad in ["tunnel-everything", "command=unquoted", "command=\"open", "no-pty,,from=\"x\""] {
            assert!(parse_line(&format!("{bad} {KEY}")).is_err(), "{bad}");
        }
    }

    #[test]
    fn from_and_expiry() {
        let e = parse_line(&format!("from=\"192.0.2.*\",expiry-time=\"20300101Z\" {KEY}")).unwrap().unwrap();
        let login = |ip: &str, now| Login { user: "u", ip: ip.parse().unwrap(), now };
        let offered = Offered::Key(e.key.clone());
        assert!(check(&offered, std::slice::from_ref(&e), &[], &login("192.0.2.5", 1_800_000_000)).is_ok());
        assert!(check(&offered, std::slice::from_ref(&e), &[], &login("198.51.100.5", 1_800_000_000)).is_err());
        assert!(check(&offered, std::slice::from_ref(&e), &[], &login("192.0.2.5", 1_900_000_000)).is_err(), "expired");
        assert_eq!(parse_expiry("20300101Z").unwrap(), 1_893_456_000);
    }

    #[test]
    fn listen_patterns() {
        let r = Restrictions { permit_listen: vec!["8080".into(), "localhost:9000".into()], ..Default::default() };
        assert!(r.may_listen("", 8080) && r.may_listen("localhost", 9000));
        assert!(!r.may_listen("", 9001) && !r.may_listen("0.0.0.0", 8080));
    }
}
