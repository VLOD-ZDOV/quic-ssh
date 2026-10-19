//! Command-line parsing for sessions, compatible with OpenSSH's `ssh`.
//!
//! Programs such as `sftp -S`, `scp -S`, `rsync -e`, `git` and `sshfs` call
//! "ssh" with getopt-style arguments (`-oKey value`, `-p22`, `-tt`, options
//! after the host name). This parser follows the same rules, so qsh can stand
//! in for ssh, and it keeps the arguments in a form that can be handed to the
//! real ssh in `--full` mode.

use std::path::PathBuf;

use crate::transport::Mode;

/// ssh options that take a value.
pub const WITH_VALUE: &str = "BbcDEeFIiJLlmOoPpQRSWw";
/// ssh options without a value.
const FLAGS: &str = "1246AaCfGgKkMNnqsTtVvXxYy";

#[derive(Debug, Default, Clone, PartialEq)]
pub struct SshArgs {
    pub destination: Option<String>,
    pub command: Vec<String>,
    pub port: Option<u16>,
    pub login: Option<String>,
    pub identities: Vec<PathBuf>,
    pub local_forwards: Vec<String>,
    pub remote_forwards: Vec<String>,
    pub dynamic_forwards: Vec<String>,
    /// `-o` options as config lines (`Key value`).
    pub options: Vec<String>,
    pub config_file: Option<PathBuf>,
    pub jump: Option<String>,
    pub stdio_forward: Option<String>,
    pub escape_char: Option<String>,
    /// `-t` count (`-tt` forces a PTY even without a local terminal).
    pub tty: u8,
    pub no_tty: bool,
    pub no_command: bool,
    pub stdin_null: bool,
    pub subsystem: bool,
    pub quiet: bool,
    pub verbose: u8,
    pub ipv4: bool,
    pub ipv6: bool,
    /// `-g`: let other hosts connect to local forwards.
    pub gateway_ports: bool,
    pub forward_agent: Option<bool>,
    /// X11 forwarding by `-X`/`-Y` (on) and `-x` (off): the last one wins;
    /// `-Y` also makes it trusted, as in ssh.
    pub x11: Option<bool>,
    pub x11_trusted: bool,
    pub print_config: bool,
    /// `-O`: a command for the connection master (`check`, `exit`, `stop`).
    pub control_command: Option<String>,
    /// `-f`: go to the background after logging in.
    pub background: bool,
    pub print_version: bool,
    pub help: bool,
    // qsh's own options
    pub full: bool,
    pub transport: Mode,
    pub accept_new_host: bool,
    /// Options in a form the real `ssh` understands (for `--full` handover).
    pub passthrough: Vec<String>,
    /// Accepted for compatibility but without effect (reported with -v).
    pub ignored: Vec<String>,
    /// ssh options qsh does not carry out, which the user may count on:
    /// warned about when qsh (not ssh) makes the connection.
    pub unapplied: Vec<String>,
    /// Why qsh cannot make this connection itself (an option it cannot
    /// carry out or does not know): with `--full`, ssh's job; else an error.
    pub refused: Option<String>,
}

fn take_value(rest: &str, it: &mut impl Iterator<Item = String>, opt: char) -> Result<String, String> {
    if !rest.is_empty() {
        return Ok(rest.to_string());
    }
    it.next().ok_or_else(|| format!("option -{opt} requires an argument"))
}

/// `Key=Value`, `Key Value` or `Key=` → `Key value` config line.
fn option_line(o: &str) -> Result<String, String> {
    let o = o.trim();
    let split = o.find(|c: char| c == '=' || c.is_whitespace()).ok_or_else(|| format!("bad -o option {o:?}"))?;
    let (k, v) = o.split_at(split);
    let v = v.trim_start_matches(|c: char| c == '=' || c.is_whitespace());
    Ok(format!("{k} {v}"))
}

/// `-o` keywords only qsh knows (ssh stops at them).
const QSH_ONLY_OPTIONS: [&str; 2] = ["PersistSession", "PredictiveEcho"];

/// Keywords the config parser carries out (lowercase).
const APPLIED_OPTIONS: &[&str] = &[
    "addkeystoagent", "addressfamily", "batchmode", "bindaddress", "bindinterface", "canonicaldomains",
    "canonicalizefallbacklocal", "canonicalizehostname", "canonicalizemaxdots", "certificatefile", "clearallforwardings",
    "compression", "connectionattempts", "connecttimeout", "controlmaster", "controlpath", "controlpersist", "dynamicforward",
    "enableescapecommandline", "escapechar", "exitonforwardfailure", "forkafterauthentication", "forwardagent", "forwardx11",
    "forwardx11timeout", "forwardx11trusted", "globalknownhostsfile", "hashknownhosts", "host", "hostkeyalias", "hostname",
    "identitiesonly", "identityagent", "identityfile", "include", "knownhostscommand", "localcommand", "localforward",
    "loglevel", "match", "numberofpasswordprompts", "obscurekeystroketiming", "passwordauthentication", "permitlocalcommand",
    "persistsession", "port", "predictiveecho", "proxycommand", "proxyjump", "remotecommand", "remoteforward", "requesttty",
    "sendenv", "serveralivecountmax", "serveraliveinterval", "sessiontype", "setenv", "stdinnull", "stricthostkeychecking",
    "tag", "tunnel", "tunneldevice", "user", "userknownhostsfile", "xauthlocation",
];

/// ssh keywords with nothing to do in qsh: its own fixed crypto (TLS 1.3),
/// logging, GSSAPI, host-based and keyboard-interactive login, old options.
const QUIET_OPTIONS: &[&str] = &[
    "casignaturealgorithms", "challengeresponseauthentication", "checkhostip", "cipher", "ciphers", "compressionlevel",
    "enablesshkeysign", "fingerprinthash", "gssapiauthentication", "gssapiclientidentity", "gssapidelegatecredentials",
    "gssapikeyexchange", "gssapirenewalforcesrekey", "gssapiserveridentity", "gssapitrustdns", "hostbasedacceptedalgorithms",
    "hostbasedauthentication", "hostbasedkeytypes", "hostkeyalgorithms", "ignoreunknown", "ipqos", "kbdinteractiveauthentication",
    "kbdinteractivedevices", "kexalgorithms", "logverbose", "macs", "nohostauthenticationforlocalhost", "preferredauthentications",
    "protocol", "proxyusefdpass", "pubkeyacceptedalgorithms", "pubkeyacceptedkeytypes", "rekeylimit", "requiredrsasize",
    "rhostsauthentication", "rhostsrsaauthentication", "rsaauthentication", "streamlocalbindmask", "syslogfacility",
    "tcpkeepalive", "updatehostkeys", "usekeychain", "useprivilegedport", "useroaming", "versionaddendum", "visualhostkey",
    "warnweakcrypto",
];

/// ssh keywords qsh does not carry out and that would make it less strict
/// than asked if skipped: refused.
const REFUSED_OPTIONS: &[&str] = &["permitremoteopen", "refuseconnection", "revokedhostkeys"];

/// Other ssh keywords qsh does not carry out: a warning.
const UNAPPLIED_OPTIONS: &[&str] = &[
    "canonicalizepermittedcnames", "channeltimeout", "gatewayports", "pkcs11provider", "pubkeyauthentication",
    "securitykeyprovider", "streamlocalbindunlink", "verifyhostkeydns",
];

/// The keyword of a `-o` value (`Key=value` or `Key value`).
fn option_keyword(v: &str) -> &str {
    v.trim_start().split(|c: char| c == '=' || c.is_whitespace()).next().unwrap_or("")
}

impl SshArgs {
    fn apply_flag(&mut self, c: char) -> Result<(), String> {
        match c {
            '4' => self.ipv4 = true,
            '6' => self.ipv6 = true,
            'A' => self.forward_agent = Some(true),
            'a' => self.forward_agent = Some(false),
            'f' => self.background = true,
            'G' => self.print_config = true,
            'g' => self.gateway_ports = true,
            'N' => self.no_command = true,
            'n' => self.stdin_null = true,
            'q' => self.quiet = true,
            's' => self.subsystem = true,
            'T' => self.no_tty = true,
            't' => self.tty += 1,
            'V' => self.print_version = true,
            'v' => self.verbose += 1,
            // X11 forwarding: untrusted (-X), trusted (-Y), off (-x).
            'X' => self.x11 = Some(true),
            'Y' => (self.x11, self.x11_trusted) = (Some(true), true),
            'x' => self.x11 = Some(false),
            // Protocol/compression/GSSAPI/syslog/multiplexing switches: nothing to do.
            // Like `ControlMaster yes` (`-MM` asks in ssh; qsh does not ask).
            'M' => {
                self.options.push("ControlMaster yes".into());
                // ssh would use its own sockets and protocol: not passed on.
                return Ok(());
            }
            // Protocol, compression, GSSAPI, syslog: nothing to do in qsh.
            '1' | '2' | 'C' | 'K' | 'k' | 'y' => self.ignored.push(format!("-{c}")),
            _ => return Err(format!("unknown option -{c}")),
        }
        self.passthrough.push(format!("-{c}"));
        Ok(())
    }

    fn apply_value(&mut self, c: char, v: String) -> Result<(), String> {
        // Several values become config lines (`-o`, `-J`, `-S`...): a line
        // break would add lines of its own (ProxyCommand, Match exec).
        if v.contains(['\n', '\r', '\0']) {
            return Err(format!("bad value for -{c}: {v:?}"));
        }
        // -p is re-added from the final port so `host:port` also reaches ssh;
        // -S and -O name qsh's sharing sockets, which ssh cannot use; ssh
        // refuses qsh's own -o keywords.
        let qsh_only = c == 'o' && QSH_ONLY_OPTIONS.iter().any(|k| option_keyword(&v).eq_ignore_ascii_case(k));
        let pass = (!matches!(c, 'p' | 'S' | 'O') && !qsh_only).then(|| v.clone());
        match c {
            'p' => {
                let p = v.parse().map_err(|_| format!("bad port {v:?}"))?;
                self.port = Some(p);
            }
            'l' if !crate::proto::valid_user_name(&v) => return Err(format!("invalid user name {v:?}")),
            'l' => self.login = Some(v),
            'i' => self.identities.push(PathBuf::from(v)),
            'L' => self.local_forwards.push(v),
            'R' => self.remote_forwards.push(v),
            'D' => self.dynamic_forwards.push(v),
            'o' => self.options.push(option_line(&v)?),
            'F' => self.config_file = Some(PathBuf::from(v)),
            'J' => self.jump = Some(v),
            'W' => self.stdio_forward = Some(v),
            'e' => self.escape_char = Some(v),
            'O' => match v.as_str() {
                "check" | "exit" | "stop" | "forward" | "cancel" => self.control_command = Some(v),
                _ => return Err(format!("unsupported -O command {v:?} (check, exit, stop, forward, cancel)")),
            },
            'S' => self.options.push(format!("ControlPath {v}")),
            'b' => self.options.push(format!("BindAddress {v}")),
            'P' => self.options.push(format!("Tag {v}")),
            'B' => self.options.push(format!("BindInterface {v}")),
            'w' => {
                self.options.push("Tunnel yes".into());
                self.options.push(format!("TunnelDevice {v}"));
            }
            'Q' => {
                self.refused.get_or_insert_with(|| "-Q (query algorithms) is not supported: qsh uses TLS 1.3 with a fixed set".into());
            }
            'E' | 'I' => self.unapplied.push(format!("-{c} {v}")),
            // Ciphers and MACs.
            _ => self.ignored.push(format!("-{c} {v}")),
        }
        if let Some(v) = pass {
            self.passthrough.push(format!("-{c}"));
            self.passthrough.push(v);
        }
        Ok(())
    }

    fn apply_long(&mut self, name: &str, value: Option<String>, it: &mut impl Iterator<Item = String>) -> Result<(), String> {
        let mut val = |v: Option<String>| v.or_else(|| it.next()).ok_or_else(|| format!("--{name} requires an argument"));
        match name {
            "full" => self.full = true,
            "accept-new-host" => self.accept_new_host = true,
            "verbose" => self.verbose += 1,
            "help" => self.help = true,
            "version" => self.print_version = true,
            "transport" => {
                self.transport = match val(value)?.as_str() {
                    "auto" => Mode::Auto,
                    "quic" => Mode::Quic,
                    "tcp" => Mode::Tcp,
                    other => return Err(format!("unknown transport {other:?} (auto, quic, tcp)")),
                }
            }
            "port" => return self.apply_value('p', val(value)?),
            "identity" => return self.apply_value('i', val(value)?),
            "login" => return self.apply_value('l', val(value)?),
            other => return Err(format!("unknown option --{other}")),
        }
        Ok(())
    }

    /// Parses arguments after the program name.
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<SshArgs, String> {
        let mut a = SshArgs::default();
        let mut it = args.into_iter();
        while let Some(arg) = it.next() {
            if arg == "--" {
                if a.destination.is_none() {
                    a.destination = it.next();
                }
                a.command.extend(it.by_ref());
                break;
            }
            if let Some(long) = arg.strip_prefix("--") {
                let (name, value) = match long.split_once('=') {
                    Some((n, v)) => (n, Some(v.to_string())),
                    None => (long, None),
                };
                a.apply_long(name, value, &mut it)?;
                continue;
            }
            if let Some(cluster) = arg.strip_prefix('-').filter(|c| !c.is_empty()) {
                for (i, c) in cluster.char_indices() {
                    if WITH_VALUE.contains(c) {
                        let v = take_value(&cluster[i + c.len_utf8()..], &mut it, c)?;
                        a.apply_value(c, v)?;
                        break;
                    } else if FLAGS.contains(c) {
                        a.apply_flag(c)?;
                    } else {
                        return Err(format!("unknown option -{c}"));
                    }
                }
                continue;
            }
            // Like ssh: options may follow the host name; the first other word starts the command.
            if a.destination.is_none() {
                a.destination = Some(arg);
            } else {
                a.command.push(arg);
                a.command.extend(it.by_ref());
                break;
            }
        }
        a.check_options();
        Ok(a)
    }

    /// Sorts the `-o` options qsh does not carry out, as ssh does with
    /// unknown ones: an unknown keyword (a typo too) is an error, unless
    /// `-o IgnoreUnknown` names it. Only qsh's verdict: ssh, with `--full`,
    /// may know a keyword of a newer OpenSSH.
    fn check_options(&mut self) {
        let ignore_unknown: Vec<String> = self
            .options
            .iter()
            .filter(|o| option_keyword(o).eq_ignore_ascii_case("ignoreunknown"))
            .flat_map(|o| o.split_whitespace().skip(1).flat_map(|v| v.split(',')).map(str::to_ascii_lowercase).collect::<Vec<_>>())
            .collect();
        for o in &self.options {
            let key = option_keyword(o).to_ascii_lowercase();
            let is = |list: &[&str]| list.contains(&key.as_str());
            if is(APPLIED_OPTIONS) {
                continue;
            }
            if is(QUIET_OPTIONS) {
                self.ignored.push(format!("-o {o}"));
            } else if is(REFUSED_OPTIONS) {
                self.refused.get_or_insert_with(|| format!("-o {}: not supported by qsh (use ssh for this)", option_keyword(o)));
            } else if is(UNAPPLIED_OPTIONS) {
                self.unapplied.push(format!("-o {o}"));
            } else if crate::pattern::name_matches(&ignore_unknown, &key) {
                self.ignored.push(format!("-o {o}"));
            } else {
                self.refused.get_or_insert_with(|| format!("bad configuration option: {}", option_keyword(o)));
            }
        }
    }

    /// The `-o` options and other switches as config lines (highest
    /// precedence). `-l` goes to the configs as the command line's user.
    pub fn override_lines(&self) -> Vec<String> {
        // Switches before -o, which does not change what they set (as in ssh).
        let mut lines: Vec<String> = match self.x11 {
            Some(true) => vec!["ForwardX11 yes".into()],
            Some(false) => vec!["ForwardX11 no".into()],
            None => Vec::new(),
        };
        if self.x11_trusted {
            lines.push("ForwardX11Trusted yes".into());
        }
        lines.extend(self.options.iter().cloned());
        if self.quiet {
            lines.push("LogLevel quiet".into());
        }
        if self.ipv4 {
            lines.push("AddressFamily inet".into());
        } else if self.ipv6 {
            lines.push("AddressFamily inet6".into());
        }
        lines
    }
}

pub const USAGE: &str = "\
usage: qsh [-46AaCfGgMNnqsTtVvx] [-D [bind:]port] [-e escape_char] [-F configfile]
           [-i identity] [-J [user@]host[:port]] [-L [bind:]port:host:hostport]
           [-l login] [-O check|exit|stop|forward|cancel] [-o option] [-p port]
           [-R [bind:]port:host:hostport] [-S ctl_path] [-W host:port]
           [--full] [--transport auto|quic|tcp] [--accept-new-host]
           [user@]host[:port] [command [argument ...]]

       qsh cp [-r] SRC DST        copy files, one side is [user@]host:path
       qsh pair [user@]host       pair with a server using a code from `qshd pair`
       qsh forget [user@]host     forget a host's key after a legitimate change
       qsh keygen [FILE]          create a new key
       qsh speed [user@]host      measure latency and throughput
       qsh ui                     interactive host menu
       qsh doctor [HOST]          find out why something does not connect
       qsh multi [-g GROUP] [-P N] [HOST...] -- COMMAND   run on several hosts

Options as in ssh(1); the default port is 4422. --full (automatic when qsh is
run as `ssh`) uses the ssh config fully and falls back to OpenSSH's ssh where
there is no qshd. See https://github.com/VLOD-ZDOV/quic-ssh";

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> SshArgs {
        SshArgs::parse(s.split_whitespace().map(String::from)).unwrap()
    }

    #[test]
    fn ssh_style_arguments() {
        let a = p("-p22 -tt -NL 8080:localhost:80 -l bob host uname -a");
        assert_eq!(a.port, Some(22));
        assert_eq!(a.tty, 2);
        assert!(a.no_command);
        assert_eq!(a.local_forwards, vec!["8080:localhost:80"]);
        assert_eq!(a.login.as_deref(), Some("bob"));
        assert_eq!(a.destination.as_deref(), Some("host"));
        assert_eq!(a.command, vec!["uname", "-a"]);
        assert_eq!(p("-Y -x host").override_lines(), ["ForwardX11 no", "ForwardX11Trusted yes"], "the last X11 switch wins");
        assert_eq!(p("-x -X host").override_lines()[0], "ForwardX11 yes");
        // Values that would become extra config lines, or odd user names.
        for bad in [["-l", "bob\nProxyCommand evil"], ["-o", "User=x\nMatch exec evil"], ["-J", "gw\rProxyCommand x"], ["-l", "$(id)"]] {
            assert!(SshArgs::parse(bad.iter().map(|s| s.to_string()).chain(["host".into()])).is_err(), "{bad:?}");
        }
    }

    /// Options qsh cannot carry out do not stop parsing: with --full, ssh
    /// gets the connection (it may know a newer keyword).
    #[test]
    fn options_qsh_cannot_carry_out() {
        let p = |args: &[&str]| SshArgs::parse(args.iter().map(|s| s.to_string())).unwrap();
        assert!(p(&["-o", "Bogus=1", "h"]).refused.unwrap().contains("Bogus"));
        assert!(p(&["-o", "IgnoreUnknown=bog*", "-o", "Bogus=1", "h"]).refused.is_none());
        assert!(p(&["-o", "RevokedHostKeys=/x", "h"]).refused.is_some());
        assert!(p(&["-Q", "kex"]).refused.is_some());
        let a = p(&["-o", "Ciphers=x", "-o", "GatewayPorts=yes", "-c", "x", "-E", "log", "h"]);
        assert!(a.refused.is_none());
        assert_eq!(a.unapplied, ["-E log", "-o GatewayPorts yes"]);
    }

    #[test]
    fn options_after_host_and_double_dash() {
        let a = p("host -v -p 2222 ls -la");
        assert_eq!((a.verbose, a.port), (1, Some(2222)));
        assert_eq!(a.command, vec!["ls", "-la"]);
        let a = p("-- host -p 1");
        assert_eq!(a.destination.as_deref(), Some("host"));
        assert_eq!(a.command, vec!["-p", "1"]);
    }

    #[test]
    fn how_sftp_scp_rsync_and_git_call_ssh() {
        // sftp -S qsh
        let a = SshArgs::parse(
            ["-oForwardX11 no", "-oPermitLocalCommand no", "-oClearAllForwardings yes", "-oForwardAgent no", "-l", "u", "-s", "--", "h", "sftp"]
                .map(String::from),
        )
        .unwrap();
        assert!(a.subsystem);
        assert_eq!(a.destination.as_deref(), Some("h"));
        assert_eq!(a.command, vec!["sftp"]);
        assert!(a.options.contains(&"ClearAllForwardings yes".to_string()));
        // rsync -e qsh
        let a = p("-l u h rsync --server -vlogDtpre.iLsfxCIvu . /dest");
        assert_eq!(a.command[0], "rsync");
        // git (OpenSSH variant)
        let a = p("-o SendEnv=GIT_PROTOCOL -p 2222 u@h git-upload-pack '/repo'");
        assert_eq!(a.options, vec!["SendEnv GIT_PROTOCOL"]);
        // sshfs
        let a = p("-x -a -oClearAllForwardings=yes -2 h -s sftp");
        assert!(a.subsystem && a.forward_agent == Some(false));
    }

    #[test]
    fn qsh_long_options_and_passthrough() {
        let a = p("-fNq --full --transport=tcp --accept-new-host -J jump -R 9000:localhost:80 host");
        assert!(a.full && a.background && a.no_command && a.quiet && a.accept_new_host);
        assert_eq!(a.transport, Mode::Tcp);
        assert_eq!(a.passthrough, vec!["-f", "-N", "-q", "-J", "jump", "-R", "9000:localhost:80"]);
    }

    #[test]
    fn connection_sharing_options() {
        let a = p("-M -S /tmp/s -O check host");
        assert_eq!(a.options, vec!["ControlMaster yes", "ControlPath /tmp/s"]);
        assert_eq!(a.control_command.as_deref(), Some("check"));
        assert!(a.passthrough.is_empty(), "ssh must not get qsh's sockets: {:?}", a.passthrough);
    }

    #[test]
    fn rejects_bad_input() {
        for bad in ["-p", "-p notaport h", "-Z h", "--nope h", "-O proxy h"] {
            assert!(SshArgs::parse(bad.split_whitespace().map(String::from)).is_err(), "{bad}");
        }
        assert_eq!(option_line("Port=22").unwrap(), "Port 22");
        assert_eq!(option_line("User  bob").unwrap(), "User bob");
    }
}
