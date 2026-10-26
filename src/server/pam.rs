//! PAM (`use_pam`, built with the `pam` feature on Linux): account checks
//! (`pam_acct_mgmt`) for every login, passwords through `pam_authenticate`,
//! and a PAM session (`pam_setcred`, `pam_open_session`) around each
//! session's program, opened in `internal-become`, so pam_limits,
//! pam_systemd, pam_loginuid and pam_env apply to it as with sshd.
//!
//! Authentication and account checks run in qshd itself, on a blocking
//! thread; the session has a PAM handle of its own in the process that
//! starts the program (credentials a module set while authenticating, a
//! Kerberos ticket say, do not carry over).

use std::ffi::{c_char, c_int, c_void, CStr, CString};

use anyhow::{bail, Context, Result};

#[repr(C)]
struct PamHandle {
    _private: [u8; 0],
}

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

type ConvFn = extern "C" fn(c_int, *mut *const PamMessage, *mut *mut PamResponse, *mut c_void) -> c_int;

#[repr(C)]
struct PamConv {
    conv: ConvFn,
    appdata_ptr: *mut c_void,
}

#[link(name = "pam")]
extern "C" {
    fn pam_start(service: *const c_char, user: *const c_char, conv: *const PamConv, handle: *mut *mut PamHandle) -> c_int;
    fn pam_end(handle: *mut PamHandle, status: c_int) -> c_int;
    fn pam_set_item(handle: *mut PamHandle, item: c_int, value: *const c_void) -> c_int;
    fn pam_get_item(handle: *const PamHandle, item: c_int, value: *mut *const c_void) -> c_int;
    fn pam_authenticate(handle: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_acct_mgmt(handle: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_setcred(handle: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_open_session(handle: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_close_session(handle: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_getenvlist(handle: *mut PamHandle) -> *mut *mut c_char;
    fn pam_strerror(handle: *mut PamHandle, code: c_int) -> *const c_char;
}

const PAM_SUCCESS: c_int = 0;
const PAM_BUF_ERR: c_int = 5;
pub const PAM_NEW_AUTHTOK_REQD: c_int = 12;
const PAM_CONV_ERR: c_int = 19;

const PAM_USER: c_int = 2;
const PAM_TTY: c_int = 3;
const PAM_RHOST: c_int = 4;

const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;
const PAM_ERROR_MSG: c_int = 3;
const PAM_TEXT_INFO: c_int = 4;
/// Linux-PAM's limit on messages in one call.
const PAM_MAX_NUM_MSG: c_int = 32;

const PAM_SILENT: c_int = 0x8000;
pub const PAM_DISALLOW_NULL_AUTHTOK: c_int = 0x0001;
const PAM_ESTABLISH_CRED: c_int = 0x0002;
const PAM_DELETE_CRED: c_int = 0x0004;
const PAM_REINITIALIZE_CRED: c_int = 0x0008;

/// What a module tells or asks.
pub enum Message<'a> {
    /// A question; the answer is shown as typed if `echo`.
    Prompt { text: &'a str, echo: bool },
    /// Text to show (`error`: an error message).
    Info { text: &'a str, error: bool },
}

/// Answers a module's messages: `None` for a question ends the conversation
/// (the module then fails).
pub type Conversation = Box<dyn FnMut(Message) -> Option<String> + Send>;

/// A PAM call that did not succeed.
#[derive(Debug)]
pub struct Error {
    pub code: c_int,
    pub text: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

impl std::error::Error for Error {}

/// A PAM transaction for one user.
pub struct Pam {
    handle: *mut PamHandle,
    /// Kept alive for the handle, which points at it.
    _conv: Box<Conversation>,
    /// Given to `pam_end`: the last call's result.
    status: c_int,
}

// The handle is used by one thread at a time.
unsafe impl Send for Pam {}

extern "C" fn converse(count: c_int, messages: *mut *const PamMessage, responses: *mut *mut PamResponse, data: *mut c_void) -> c_int {
    if count <= 0 || count > PAM_MAX_NUM_MSG || messages.is_null() || responses.is_null() || data.is_null() {
        return PAM_CONV_ERR;
    }
    // Freed by the module (calloc'd, as PAM expects).
    let out = unsafe { libc::calloc(count as usize, std::mem::size_of::<PamResponse>()) } as *mut PamResponse;
    if out.is_null() {
        return PAM_BUF_ERR;
    }
    let conv = unsafe { &mut *(data as *mut Conversation) };
    // A panic must not unwind into C (that aborts, here possibly as root
    // in the middle of opening a session): it counts as no answer.
    let mut conv = |m: Message| std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| conv(m))).ok().flatten();
    let fail = |out: *mut PamResponse, filled: usize| {
        for i in 0..filled {
            let r = unsafe { &mut *out.add(i) };
            if !r.resp.is_null() {
                // Answers may be passwords.
                unsafe {
                    let len = libc::strlen(r.resp);
                    std::ptr::write_bytes(r.resp, 0, len);
                    libc::free(r.resp as *mut c_void);
                }
            }
        }
        unsafe { libc::free(out as *mut c_void) };
        PAM_CONV_ERR
    };
    for i in 0..count as usize {
        // Linux-PAM passes an array of pointers to messages.
        let msg = unsafe { *messages.add(i) };
        if msg.is_null() {
            return fail(out, i);
        }
        let msg = unsafe { &*msg };
        let text = if msg.msg.is_null() { String::new() } else { unsafe { CStr::from_ptr(msg.msg) }.to_string_lossy().into_owned() };
        let answer = match msg.msg_style {
            PAM_PROMPT_ECHO_OFF | PAM_PROMPT_ECHO_ON => match conv(Message::Prompt { text: &text, echo: msg.msg_style == PAM_PROMPT_ECHO_ON }) {
                Some(a) => {
                    let a = zeroize::Zeroizing::new(a);
                    let c = match CString::new(a.as_bytes()) {
                        Ok(c) => c,
                        Err(e) => {
                            zeroize::Zeroize::zeroize(&mut e.into_vec());
                            return fail(out, i);
                        }
                    };
                    let c = zeroize::Zeroizing::new(c.into_bytes_with_nul());
                    let copy = unsafe { libc::strdup(c.as_ptr() as *const c_char) };
                    if copy.is_null() {
                        return fail(out, i);
                    }
                    copy
                }
                None => return fail(out, i),
            },
            PAM_ERROR_MSG | PAM_TEXT_INFO => {
                conv(Message::Info { text: &text, error: msg.msg_style == PAM_ERROR_MSG });
                std::ptr::null_mut()
            }
            _ => return fail(out, i),
        };
        unsafe { (*out.add(i)).resp = answer };
    }
    unsafe { *responses = out };
    PAM_SUCCESS
}

impl Pam {
    /// Starts a transaction with `service` (a file in /etc/pam.d) for `user`.
    pub fn start(service: &str, user: &str, conv: Conversation) -> Result<Pam> {
        let service_c = CString::new(service).context("bad PAM service name")?;
        let user_c = CString::new(user).context("bad user name")?;
        let mut conv = Box::new(conv);
        let pam_conv = PamConv { conv: converse, appdata_ptr: &mut *conv as *mut Conversation as *mut c_void };
        let mut handle = std::ptr::null_mut();
        // PAM keeps a copy of `pam_conv`; `conv` stays where it is, in its box.
        let code = unsafe { pam_start(service_c.as_ptr(), user_c.as_ptr(), &pam_conv, &mut handle) };
        if code != PAM_SUCCESS || handle.is_null() {
            bail!("pam_start({service}) failed (code {code})");
        }
        Ok(Pam { handle, _conv: conv, status: PAM_SUCCESS })
    }

    fn check(&mut self, code: c_int) -> Result<(), Error> {
        self.status = code;
        if code == PAM_SUCCESS {
            return Ok(());
        }
        let text = unsafe { pam_strerror(self.handle, code) };
        let text = if text.is_null() { format!("PAM error {code}") } else { unsafe { CStr::from_ptr(text) }.to_string_lossy().into_owned() };
        Err(Error { code, text })
    }

    fn set_item(&mut self, item: c_int, value: &str) -> Result<(), Error> {
        let value = CString::new(value).map_err(|_| Error { code: PAM_BUF_ERR, text: "bad PAM item".into() })?;
        let code = unsafe { pam_set_item(self.handle, item, value.as_ptr() as *const c_void) };
        self.check(code)
    }

    /// The client's address (`PAM_RHOST`), for pam_access and the logs.
    pub fn set_rhost(&mut self, host: &str) -> Result<(), Error> {
        self.set_item(PAM_RHOST, host)
    }

    /// The terminal (`PAM_TTY`): its path, or `ssh` without one, like sshd
    /// (pam_access and pam_securetty know that name).
    pub fn set_tty(&mut self, tty: &str) -> Result<(), Error> {
        self.set_item(PAM_TTY, tty)
    }

    /// `PAM_USER` as it is now: a module may have changed it.
    pub fn user(&self) -> Option<String> {
        let mut value: *const c_void = std::ptr::null();
        let code = unsafe { pam_get_item(self.handle, PAM_USER, &mut value) };
        (code == PAM_SUCCESS && !value.is_null()).then(|| unsafe { CStr::from_ptr(value as *const c_char) }.to_string_lossy().into_owned())
    }

    pub fn authenticate(&mut self, flags: c_int) -> Result<(), Error> {
        let code = unsafe { pam_authenticate(self.handle, flags) };
        self.check(code)
    }

    pub fn acct_mgmt(&mut self, flags: c_int) -> Result<(), Error> {
        let code = unsafe { pam_acct_mgmt(self.handle, flags) };
        self.check(code)
    }

    /// Credentials and the session, in the order login(1) uses.
    pub fn open_session(&mut self) -> Result<(), Error> {
        let code = unsafe { pam_setcred(self.handle, PAM_ESTABLISH_CRED) };
        self.check(code)?;
        let code = unsafe { pam_open_session(self.handle, 0) };
        if let Err(e) = self.check(code) {
            unsafe { pam_setcred(self.handle, PAM_DELETE_CRED | PAM_SILENT) };
            return Err(e);
        }
        // Some modules (pam_krb5, pam_ecryptfs) need the session first.
        unsafe { pam_setcred(self.handle, PAM_REINITIALIZE_CRED) };
        Ok(())
    }

    pub fn close_session(&mut self) {
        let code = unsafe { pam_close_session(self.handle, PAM_SILENT) };
        self.status = code;
        unsafe { pam_setcred(self.handle, PAM_DELETE_CRED | PAM_SILENT) };
    }

    /// Variables the modules set (pam_env, pam_systemd's `XDG_RUNTIME_DIR`).
    pub fn env(&self) -> Vec<(String, String)> {
        let list = unsafe { pam_getenvlist(self.handle) };
        let mut vars = Vec::new();
        if list.is_null() {
            return vars;
        }
        let mut i = 0;
        loop {
            let item = unsafe { *list.add(i) };
            if item.is_null() {
                break;
            }
            let text = unsafe { CStr::from_ptr(item) }.to_string_lossy().into_owned();
            if let Some((k, v)) = text.split_once('=').filter(|(k, _)| !k.is_empty()) {
                vars.push((k.to_string(), v.to_string()));
            }
            unsafe { libc::free(item as *mut c_void) };
            i += 1;
        }
        unsafe { libc::free(list as *mut c_void) };
        vars
    }
}

impl Drop for Pam {
    fn drop(&mut self) {
        unsafe { pam_end(self.handle, self.status) };
    }
}

/// Messages of modules where nobody can answer: shown in qshd's log,
/// questions refused.
fn log_only(user: String) -> Conversation {
    Box::new(move |m| {
        match m {
            Message::Info { text, .. } => tracing::info!("PAM ({user}): {}", text.trim()),
            Message::Prompt { text, .. } => tracing::warn!("PAM ({user}) asks {:?}, which cannot be answered here", text.trim()),
        }
        None
    })
}

/// How an account check went.
pub enum Account {
    Ok,
    /// The password has expired: logins with it are refused (qshd cannot
    /// have it changed), keys still work.
    PasswordExpired,
    Refused(String),
}

/// `pam_acct_mgmt` for a login made with a key (pam_access, pam_nologin,
/// pam_time, an expired account). Blocks.
pub fn account(service: &str, user: &str, rhost: &str) -> Account {
    let run = || -> Result<Result<(), Error>> {
        let mut pam = Pam::start(service, user, log_only(user.to_string()))?;
        pam.set_rhost(rhost)?;
        pam.set_tty("ssh")?;
        Ok(pam.acct_mgmt(PAM_SILENT))
    };
    match run() {
        Ok(Ok(())) => Account::Ok,
        Ok(Err(e)) if e.code == PAM_NEW_AUTHTOK_REQD => Account::PasswordExpired,
        Ok(Err(e)) => Account::Refused(e.text),
        Err(e) => Account::Refused(format!("{e:#}")),
    }
}

/// Variables a PAM module may not set (sshd keeps them from PAM too).
fn reserved(name: &str) -> bool {
    name.starts_with("SSH_") || ["HOME", "USER", "LOGNAME", "SHELL", "TERM", "DISPLAY"].contains(&name)
}

/// The session's variables with the modules' ones: these may replace the
/// built-in `PATH` (pam_env's from /etc/environment) and add variables,
/// but never replace what the server or the client set, or the reserved ones.
/// `session` starts with the base variables (`User::env`), once each; a
/// name given again later was set by the server or the client.
pub fn merge_env(session: Vec<(String, String)>, pam: &[(String, String)]) -> Vec<(String, String)> {
    let count = |name: &str| session.iter().filter(|(k, _)| k == name).count();
    let mut base: Vec<(String, String)> = Vec::new();
    for (k, v) in pam {
        let free = match count(k) {
            0 => true,
            1 => k == "PATH",
            _ => false,
        };
        if free && !reserved(k) {
            base.push((k.clone(), v.clone()));
        }
    }
    // Applied in order: the modules' first, then the session's, minus a
    // PATH the modules replaced.
    let replaced_path = base.iter().any(|(k, _)| k == "PATH");
    base.extend(session.into_iter().filter(|(k, _)| !(replaced_path && k == "PATH")));
    base
}

/// The process that runs the program, below the one holding its PAM session.
pub struct SessionChild {
    /// Variables the modules set, for the program.
    pub env: Vec<(String, String)>,
    parent: nix::unistd::Pid,
}

impl SessionChild {
    /// A parent killed outright cannot close the session; the program then
    /// gets a hangup, as when a terminal goes away. Call after switching
    /// to the user: a change of user clears this setting.
    pub fn hang_up_with_parent(&self) -> Result<()> {
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGHUP) };
        if nix::unistd::getppid() != self.parent {
            bail!("the process holding the PAM session is gone");
        }
        Ok(())
    }
}

/// How long the program has after a hangup or SIGTERM before it is
/// killed, in seconds: less than qshd waits before it kills this process
/// (`exec::DRAIN_GRACE`), so the session is closed first.
const HANGUP_GRACE: u32 = 1;

/// Opens the PAM session of a session's program and stays to close it: the
/// process forks, the parent waits for the child and exits with its
/// status, the child returns the modules' variables and goes on to run the
/// program as `user` (its uid must be `uid`). `tty`: the terminal's path,
/// if the session has one. Called by `internal-become` as root, before it
/// switches to the user.
pub fn run_session(service: &str, user: &str, uid: u32, rhost: &str, tty: Option<&str>) -> Result<SessionChild> {
    use nix::sys::signal::{sigaction, sigprocmask, SaFlags, SigAction, SigHandler, SigSet, SigmaskHow, Signal};
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::{fork, ForkResult, Pid};
    use std::sync::atomic::{AtomicI32, Ordering};

    // The name, not the uid, is what logged in: with a uid that several
    // accounts share, the first one in passwd may be another.
    match nix::unistd::User::from_name(user) {
        Ok(Some(pw)) if pw.uid.as_raw() == uid => {}
        _ => bail!("PAM session: {user:?} is not the account with uid {uid}"),
    }
    // Root's memory (the session's variables, the X11 cookie, what the
    // modules hold) never goes to a core file, whatever limit pam_limits
    // set or however the program ends (this process re-raises its signal).
    // The program is dumpable again once it runs (exec resets this).
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
    // What modules print (pam_lastlog, pam_mail) goes to the session's
    // output; a terminal already gone is no reason to fail.
    let conv: Conversation = Box::new(|m| {
        if let Message::Info { text, .. } = m {
            use std::io::Write;
            let _ = writeln!(std::io::stderr(), "{text}");
        }
        None
    });
    let mut pam = Pam::start(service, user, conv)?;
    pam.set_rhost(rhost)?;
    pam.set_tty(tty.unwrap_or("ssh"))?;
    pam.open_session().map_err(|e| anyhow::anyhow!("PAM session setup failed: {e}"))?;
    let env = pam.env();

    static CHILD: AtomicI32 = AtomicI32::new(0);
    /// A hangup or SIGTERM goes on to the program, which gets
    /// [`HANGUP_GRACE`] to end before it is killed (see `kill_child`).
    extern "C" fn pass_on(signal: c_int) {
        let pid = CHILD.load(Ordering::Relaxed);
        if pid > 0 {
            unsafe {
                libc::kill(pid, signal);
                let left = libc::alarm(HANGUP_GRACE);
                if left != 0 {
                    // An earlier one is running: keep its deadline.
                    libc::alarm(left);
                }
            }
        }
    }
    /// The program, and its own process group if it made one (a shell),
    /// as qshd kills a session's group.
    extern "C" fn kill_child(_: c_int) {
        let pid = CHILD.load(Ordering::Relaxed);
        if pid > 0 {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
                libc::kill(pid, libc::SIGKILL);
            }
        }
    }
    // Signals that arrive while forking wait until the parent can pass them on.
    let mut held = SigSet::empty();
    held.add(Signal::SIGHUP);
    held.add(Signal::SIGTERM);
    let mut before = SigSet::empty();
    sigprocmask(SigmaskHow::SIG_BLOCK, Some(&held), Some(&mut before))?;
    let parent = nix::unistd::getpid();
    match unsafe { fork() } {
        Err(e) => {
            let _ = sigprocmask(SigmaskHow::SIG_SETMASK, Some(&before), None);
            pam.close_session();
            bail!("fork: {e}")
        }
        Ok(ForkResult::Child) => {
            let _ = sigprocmask(SigmaskHow::SIG_SETMASK, Some(&before), None);
            // The parent's handle stays with the parent (pam_end would close the session).
            std::mem::forget(pam);
            // Descriptors the modules opened (D-Bus, syslog) are not the program's.
            crate::platform::close_inherited_fds();
            Ok(SessionChild { env, parent })
        }
        Ok(ForkResult::Parent { child }) => {
            // No core file, even with a limit the modules raised.
            let _ = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0);
            CHILD.store(child.as_raw(), Ordering::Relaxed);
            // A hangup (of the terminal, or from qshd) and SIGTERM go on to the
            // program; ^C and ^\ reach it from its terminal on their own.
            let forward = SigAction::new(SigHandler::Handler(pass_on), SaFlags::SA_RESTART, SigSet::empty());
            let kill = SigAction::new(SigHandler::Handler(kill_child), SaFlags::SA_RESTART, SigSet::empty());
            let ignore = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
            unsafe {
                let _ = sigaction(Signal::SIGHUP, &forward);
                let _ = sigaction(Signal::SIGTERM, &forward);
                let _ = sigaction(Signal::SIGALRM, &kill);
                let _ = sigaction(Signal::SIGINT, &ignore);
                let _ = sigaction(Signal::SIGQUIT, &ignore);
            }
            let _ = sigprocmask(SigmaskHow::SIG_SETMASK, Some(&before), None);
            // The program's output ends when it ends, not when this process does.
            if let Ok(null) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null") {
                use std::os::fd::AsRawFd;
                for fd in 0..3 {
                    unsafe { libc::dup2(null.as_raw_fd(), fd) };
                }
            }
            let status = loop {
                match waitpid(Pid::from_raw(child.as_raw()), None) {
                    Ok(s @ (WaitStatus::Exited(..) | WaitStatus::Signaled(..))) => break s,
                    Ok(_) | Err(nix::errno::Errno::EINTR) => continue,
                    Err(_) => break WaitStatus::Exited(child, 1),
                }
            };
            unsafe { libc::alarm(0) };
            pam.close_session();
            drop(pam);
            match status {
                WaitStatus::Signaled(_, signal, _) => {
                    // Ended by a signal: end the same way, so qshd reports it
                    // (no core file: see PR_SET_DUMPABLE and RLIMIT_CORE above).
                    unsafe {
                        let _ = sigaction(signal, &SigAction::new(SigHandler::SigDfl, SaFlags::empty(), SigSet::empty()));
                    }
                    let mut only = SigSet::empty();
                    only.add(signal);
                    let _ = sigprocmask(SigmaskHow::SIG_UNBLOCK, Some(&only), None);
                    let _ = nix::sys::signal::raise(signal);
                    std::process::exit(128 + signal as i32)
                }
                WaitStatus::Exited(_, code) => std::process::exit(code),
                _ => std::process::exit(1),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::merge_env;

    fn vars(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn modules_do_not_override_the_server_or_the_client() {
        let session = vars(&[("HOME", "/h"), ("PATH", "/bin"), ("LANG", "C.UTF-8"), ("SSH_ORIGINAL_COMMAND", "ls"), ("TZ", "UTC")]);
        let pam = vars(&[("PATH", "/usr/local/bin:/bin"), ("LANG", "de_DE"), ("SSH_ORIGINAL_COMMAND", "rm"), ("HOME", "/x"), ("TZ", "x"), ("XDG_RUNTIME_DIR", "/run/user/1")]);
        let merged: std::collections::HashMap<_, _> = merge_env(session, &pam).into_iter().collect();
        assert_eq!(merged["PATH"], "/usr/local/bin:/bin", "the built-in PATH gives way");
        assert_eq!(merged["LANG"], "C.UTF-8");
        assert_eq!(merged["SSH_ORIGINAL_COMMAND"], "ls");
        assert_eq!(merged["HOME"], "/h");
        assert_eq!(merged["TZ"], "UTC");
        assert_eq!(merged["XDG_RUNTIME_DIR"], "/run/user/1");
        // A PATH from set_env (the second one) stays.
        let session = vars(&[("PATH", "/bin"), ("PATH", "/opt/bin")]);
        let merged = merge_env(session, &vars(&[("PATH", "/pam")]));
        assert_eq!(merged.iter().rev().find(|(k, _)| k == "PATH").unwrap().1, "/opt/bin");
    }
}
