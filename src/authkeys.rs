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

pub use crate::pattern::endpoint_matches;

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
    let n = |r: std::ops::Range<usize>| digits.get(r).map(|s| s.parse::<i8>().unwrap_or(-1)).unwrap_or(0);
    let year: i16 = digits[0..4].parse()?;
    let time = jiff::civil::DateTime::new(year, n(4..6), n(6..8), n(8..10), n(10..12), n(12..14), 0)
        .with_context(|| format!("bad expiry-time {v:?}"))?;
    let zone = if utc { jiff::tz::TimeZone::UTC } else { jiff::tz::TimeZone::system() };
    let t = time.to_zoned(zone).context("bad expiry-time")?.timestamp().as_second();
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
        // Like OpenSSH: a second command, from or principals makes the line
        // unusable (a later one must not widen an earlier restriction), and
        // the earliest expiry-time counts.
        let once = |set: bool| if set { Err(anyhow::anyhow!("option {name} given more than once")) } else { Ok(()) };
        match name.as_str() {
            "command" => {
                once(r.command.is_some())?;
                r.command = Some(need(value)?);
            }
            "from" => {
                once(entry.from.is_some())?;
                entry.from = Some(need(value)?);
            }
            "permitopen" => r.permit_open.push(need(value)?),
            "permitlisten" => r.permit_listen.push(need(value)?),
            "expiry-time" => {
                let t = parse_expiry(&need(value)?)?;
                entry.expiry = Some(entry.expiry.map_or(t, |e| e.min(t)));
            }
            "principals" => {
                once(entry.principals.is_some())?;
                entry.principals = Some(need(value)?.split(',').map(|s| s.trim().to_string()).collect());
            }
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
    /// `authorized_principals_file`: the principals that certificates from
    /// `trusted_user_ca_keys` must name instead of the user name.
    pub principals: Option<&'a [AuthorizedPrincipal]>,
}

/// One line of an authorized principals file: `[options] principal`, with
/// the options of authorized_keys (`command=`, `from=`...).
#[derive(Clone, Debug)]
pub struct AuthorizedPrincipal {
    pub name: String,
    /// The options, held by an entry whose key is a placeholder.
    pub entry: AuthorizedKey,
}

/// A key that only carries the options of a principals line.
const PLACEHOLDER_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Parses an authorized principals file; bad lines are reported and skipped.
pub fn parse_principals(text: &str, mut bad: impl FnMut(usize, anyhow::Error)) -> Vec<AuthorizedPrincipal> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // The principal is the last word; anything before it is options.
        let (options, name) = match line.rsplit_once(char::is_whitespace) {
            Some((o, n)) => (o.trim(), n),
            None => ("", line),
        };
        let parsed = if options.is_empty() { parse_line(PLACEHOLDER_KEY) } else { parse_line(&format!("{options} {PLACEHOLDER_KEY}")) };
        match parsed {
            Ok(Some(entry)) if !entry.cert_authority && entry.principals.is_none() => {
                out.push(AuthorizedPrincipal { name: name.to_string(), entry })
            }
            Ok(_) => bad(i + 1, anyhow::anyhow!("cert-authority and principals= do not belong in a principals file")),
            Err(e) => bad(i + 1, e),
        }
    }
    out
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
    // A cert-authority line must allow no-touch-required too (as in OpenSSH);
    // a CA trusted for the whole server leaves it to the certificate.
    let mut line_allows_no_touch = true;
    if trusted_cas.contains(ca) {
        match login.principals {
            None => {
                if !principals.iter().any(|p| p == login.user) {
                    return Err(format!("certificate is not valid for {}", login.user));
                }
                grant = Some(Grant::default());
            }
            Some(lines) => {
                let mut reason = format!("certificate principals {principals:?} are not in the authorized principals file");
                for line in lines.iter().filter(|l| principals.contains(&l.name)) {
                    match entry_usable(&line.entry, login) {
                        Ok(()) => {
                            grant = Some(Grant {
                                restrictions: line.entry.restrictions.clone(),
                                require_presence: false,
                                require_verified: line.entry.verify_required,
                            });
                            line_allows_no_touch = line.entry.no_touch_required;
                            break;
                        }
                        Err(r) => reason = r,
                    }
                }
                if grant.is_none() {
                    return Err(reason);
                }
            }
        }
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
            line_allows_no_touch = e.no_touch_required;
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
    grant.require_presence = is_security_key(cert.public_key()) && !(ext.contains_key("no-touch-required") && line_allows_no_touch);
    Ok(grant)
}

/// Whether `signature` is of the kind `key` makes. The signature's own
/// algorithm name must not decide how it is checked: ssh-key verifies a
/// security-key signature by the key's type whatever the signature claims
/// to be, so a relabelled one would skip the touch and PIN checks (OpenSSH
/// refuses such a signature, too).
pub fn signature_fits(key: &KeyData, signature: &ssh_key::Signature) -> bool {
    match (key.algorithm(), signature.algorithm()) {
        (Algorithm::Rsa { .. }, Algorithm::Rsa { hash }) => hash.is_some(),
        (k, s) => k == s,
    }
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
    use super::signature_fits;

    #[test]
    fn signatures_must_match_the_key_type() {
        let sig = |alg: Algorithm, len: usize| ssh_key::Signature::new(alg, vec![1; len]).unwrap();
        let sk = KeyData::SkEd25519(ssh_key::public::SkEd25519::new(ssh_key::public::Ed25519PublicKey([7; 32]), "ssh:"));
        assert!(signature_fits(&sk, &sig(Algorithm::SkEd25519, 69)));
        assert!(!signature_fits(&sk, &sig(Algorithm::Rsa { hash: Some(ssh_key::HashAlg::Sha256) }, 69)), "relabelled as RSA");
        assert!(!signature_fits(&sk, &sig(Algorithm::Ed25519, 64)));
        let ed = KeyData::Ed25519(ssh_key::public::Ed25519PublicKey([7; 32]));
        assert!(signature_fits(&ed, &sig(Algorithm::Ed25519, 64)));
        assert!(!signature_fits(&ed, &sig(Algorithm::SkEd25519, 69)));
    }

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
        let login = |ip: &str, now| Login { user: "u", ip: ip.parse().unwrap(), now, principals: None };
        let offered = Offered::Key(e.key.clone());
        assert!(check(&offered, std::slice::from_ref(&e), &[], &login("192.0.2.5", 1_800_000_000)).is_ok());
        assert!(check(&offered, std::slice::from_ref(&e), &[], &login("198.51.100.5", 1_800_000_000)).is_err());
        assert!(check(&offered, std::slice::from_ref(&e), &[], &login("192.0.2.5", 1_900_000_000)).is_err(), "expired");
        assert_eq!(parse_expiry("20300101Z").unwrap(), 1_893_456_000);
        assert_eq!(parse_expiry("203001011230Z").unwrap(), 1_893_456_000 + 12 * 3600 + 30 * 60);
        assert_eq!(parse_expiry("20300101123045z").unwrap(), 1_893_456_000 + 12 * 3600 + 30 * 60 + 45);
        for bad in ["20301301", "20300132", "203001012500", "2030", "2030010a", "-0300101"] {
            assert!(parse_expiry(bad).is_err(), "{bad}");
        }
        // Local time: within a day of UTC midnight.
        let local = parse_expiry("20300101").unwrap() as i64;
        assert!((local - 1_893_456_000).abs() <= 14 * 3600, "{local}");
    }

    /// A second from/command/principals cannot widen the first; the earliest expiry counts.
    #[test]
    fn repeated_options() {
        for twice in ["from=\"192.0.2.1\",from=\"*\"", "command=\"a\",command=\"b\"", "principals=\"a\",principals=\"b\""] {
            assert!(parse_line(&format!("{twice} {KEY}")).is_err(), "{twice}");
        }
        let e = parse_line(&format!("expiry-time=\"20300101Z\",expiry-time=\"20400101Z\" {KEY}")).unwrap().unwrap();
        assert_eq!(e.expiry, Some(1_893_456_000));
    }

    #[test]
    fn listen_patterns() {
        let r = Restrictions { permit_listen: vec!["8080".into(), "localhost:9000".into()], ..Default::default() };
        assert!(r.may_listen("", 8080) && r.may_listen("localhost", 9000));
        assert!(!r.may_listen("", 9001) && !r.may_listen("0.0.0.0", 8080));
    }

    #[test]
    fn principals_file() {
        let mut bad = 0;
        let list = parse_principals(
            "# comment\nalice\ncommand=\"echo hi\",from=\"10.0.0.0/8\" deploy\ncert-authority x\nno-such-option y\n",
            |_, _| bad += 1,
        );
        assert_eq!(bad, 2);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "alice");
        assert!(list[0].entry.restrictions.command.is_none());
        assert_eq!(list[1].name, "deploy");
        assert_eq!(list[1].entry.restrictions.command.as_deref(), Some("echo hi"));
        assert_eq!(list[1].entry.from.as_deref(), Some("10.0.0.0/8"));
    }
}
