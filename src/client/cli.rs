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
    pub print_config: bool,
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
            'X' | 'Y' => {
                if !self.quiet {
                    eprintln!("qsh: X11 forwarding is not supported (-{c} ignored)");
                }
            }
            // Protocol/compression/GSSAPI/syslog/multiplexing switches: nothing to do.
            '1' | '2' | 'C' | 'K' | 'k' | 'M' | 'x' | 'y' => self.ignored.push(format!("-{c}")),
            _ => return Err(format!("unknown option -{c}")),
        }
        self.passthrough.push(format!("-{c}"));
        Ok(())
    }

    fn apply_value(&mut self, c: char, v: String) -> Result<(), String> {
        let pass = (c != 'p').then(|| v.clone());
        match c {
            'p' => {
                let p = v.parse().map_err(|_| format!("bad port {v:?}"))?;
                self.port = Some(p);
            }
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
            'O' => return Err("control commands (-O) are not supported: qsh has no connection multiplexing".into()),
            'w' => return Err("tunnel devices (-w) are not supported".into()),
            // Bind address/interface, ciphers, MACs, logging, PKCS#11, tags, queries.
            _ => self.ignored.push(format!("-{c} {v}")),
        }
        // -p is re-added from the final port so `host:port` also reaches ssh.
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
        Ok(a)
    }

    /// The `-o` options followed by `-l` as config lines (highest precedence).
    pub fn override_lines(&self) -> Vec<String> {
        let mut lines = self.options.clone();
        if let Some(l) = &self.login {
            lines.push(format!("User {l}"));
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
usage: qsh [-46AaCfGgNnqsTtVvx] [-D [bind:]port] [-e escape_char] [-F configfile]
           [-i identity] [-J [user@]host[:port]] [-L [bind:]port:host:hostport]
           [-l login] [-o option] [-p port] [-R [bind:]port:host:hostport]
           [-W host:port] [--full] [--transport auto|quic|tcp] [--accept-new-host]
           [user@]host[:port] [command [argument ...]]

       qsh cp [-r] SRC DST        copy files, one side is [user@]host:path
       qsh pair [user@]host CODE  pair with a server using a code from `qshd pair`
       qsh keygen [FILE]          create a new key
       qsh speed [user@]host      measure latency and throughput
       qsh ui                     interactive host menu

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
    fn rejects_bad_input() {
        for bad in ["-p", "-p notaport h", "-Z h", "--nope h", "-O check h"] {
            assert!(SshArgs::parse(bad.split_whitespace().map(String::from)).is_err(), "{bad}");
        }
        assert_eq!(option_line("Port=22").unwrap(), "Port 22");
        assert_eq!(option_line("User  bob").unwrap(), "User bob");
    }
}
