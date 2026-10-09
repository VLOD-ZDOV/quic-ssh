//! Forwarding: local (`-L`), remote (`-R`), dynamic SOCKS (`-D`, and `-R`
//! with only a port), and stdio (`-W`). Either end of `-L`/`-R` may be a TCP
//! port or a Unix socket path. A [`Forwarder`] keeps the active forwards of
//! a connection, so they can be added and cancelled while it runs (`~C`,
//! `-O forward`, `-O cancel`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::AbortHandle;
use tracing::{debug, warn};

use crate::proto::{expect_ok, read_msg, write_msg, Opened, Reply, Request};
use crate::transport::{Conn, RecvHalf, SendHalf};

/// Where a forward listens.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Listen {
    /// `bind`: `None` means the default (loopback, or all with `-g`).
    Tcp { bind: Option<String>, port: u16 },
    Unix(String),
}

/// Where its connections go.
#[derive(Debug, Clone, PartialEq)]
pub enum Dest {
    Tcp { host: String, port: u16 },
    Unix(String),
    /// A SOCKS proxy decides per connection (`-D`, `-R port`).
    Socks,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Forward {
    pub listen: Listen,
    pub dest: Dest,
}

/// Splits on ':' while keeping `[v6:addr]` together and unbracketed.
fn split_spec(s: &str) -> Result<Vec<String>> {
    let mut parts = Vec::new();
    let mut rest = s;
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix('[') {
            let (inner, after) = r.split_once(']').context("unclosed '['")?;
            parts.push(inner.to_string());
            rest = after.strip_prefix(':').unwrap_or(after);
        } else {
            let (p, after) = rest.split_once(':').unwrap_or((rest, ""));
            parts.push(p.to_string());
            rest = after;
        }
    }
    Ok(parts)
}

fn parse_port(p: &str, spec: &str) -> Result<u16> {
    p.parse::<u16>().with_context(|| format!("invalid port {p:?} in {spec:?}"))
}

/// A Unix socket path, as ssh tells them from host names: it has a `/`.
fn is_path(p: &str) -> bool {
    p.contains('/')
}

fn parse_listen(parts: &[String], spec: &str) -> Result<Listen> {
    match parts {
        [p] if is_path(p) => Ok(Listen::Unix(p.clone())),
        [p] => Ok(Listen::Tcp { bind: None, port: parse_port(p, spec)? }),
        [b, p] if !is_path(b) => Ok(Listen::Tcp { bind: Some(b.clone()), port: parse_port(p, spec)? }),
        _ => bail!("bad listen address in {spec:?}"),
    }
}

impl Forward {
    /// `-L`/`-R`: `[bind:]port:host:hostport`, `[bind:]port:/socket`,
    /// `/socket:host:hostport` or `/socket:/socket`.
    pub fn parse(s: &str) -> Result<Forward> {
        let parts = split_spec(s)?;
        let n = parts.len();
        let (dest, listen) = match parts.last() {
            Some(last) if n >= 2 && is_path(last) => (Dest::Unix(last.clone()), &parts[..n - 1]),
            Some(last) if n >= 3 => (Dest::Tcp { host: parts[n - 2].clone(), port: parse_port(last, s)? }, &parts[..n - 2]),
            _ => bail!("expected [bind_address:]port:host:hostport (or a socket path on either side), got {s:?}"),
        };
        Ok(Forward { listen: parse_listen(listen, s)?, dest })
    }

    /// `-R`: as [`Forward::parse`], or `[bind:]port` alone for a SOCKS
    /// proxy on the server whose connections go out from here.
    pub fn parse_remote(s: &str) -> Result<Forward> {
        let parts = split_spec(s)?;
        match parts.as_slice() {
            [p] | [_, p] if !is_path(p) && p.parse::<u16>().is_ok() && !parts.iter().any(|x| is_path(x)) => {
                Ok(Forward { listen: parse_listen(&parts, s)?, dest: Dest::Socks })
            }
            _ => Forward::parse(s),
        }
    }

    /// `-D`: `[bind:]port`.
    pub fn parse_dynamic(s: &str) -> Result<Forward> {
        let parts = split_spec(s)?;
        match parts.as_slice() {
            [p] | [_, p] if !is_path(p) => Ok(Forward { listen: parse_listen(&parts, s)?, dest: Dest::Socks }),
            _ => bail!("expected [bind_address:]port, got {s:?}"),
        }
    }

    pub fn describe(&self) -> String {
        let listen = match &self.listen {
            Listen::Tcp { bind: Some(b), port } if b.contains(':') => format!("[{b}]:{port}"),
            Listen::Tcp { bind: Some(b), port } => format!("{b}:{port}"),
            Listen::Tcp { bind: None, port } => port.to_string(),
            Listen::Unix(p) => p.clone(),
        };
        match &self.dest {
            Dest::Tcp { host, port } => format!("{listen}:{host}:{port}"),
            Dest::Unix(p) => format!("{listen}:{p}"),
            Dest::Socks => listen,
        }
    }
}

/// Binds local listeners. The default (and `localhost`) means loopback, both
/// IPv4 and IPv6; `-g`, `*` or an empty address mean every interface.
async fn bind_local(bind: Option<&str>, port: u16, gateway: bool) -> Result<Vec<TcpListener>> {
    let any = || vec![SocketAddr::from(([0u8; 4], port)), SocketAddr::from(([0u16; 8], port))];
    let addrs: Vec<SocketAddr> = match bind {
        None if gateway => any(),
        None => vec![SocketAddr::from(([127, 0, 0, 1], port)), SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 1], port))],
        Some("" | "*") => any(),
        Some(b) => tokio::net::lookup_host((b, port)).await.with_context(|| format!("cannot resolve {b}"))?.collect(),
    };
    let mut listeners = Vec::new();
    let mut last_err = None;
    for addr in addrs {
        match TcpListener::bind(addr).await {
            Ok(l) => listeners.push(l),
            Err(e) => last_err = Some(e),
        }
    }
    match (listeners.is_empty(), last_err) {
        (true, Some(e)) => Err(e).with_context(|| format!("cannot listen on port {port}")),
        (true, None) => bail!("no address to listen on for port {port}"),
        _ => Ok(listeners),
    }
}

/// How long a SOCKS client may take to say where it wants to go.
const SOCKS_HANDSHAKE: std::time::Duration = std::time::Duration::from_secs(30);

/// How long repeated failures to reach the same target stay hidden.
const QUIET_REPEATS: std::time::Duration = std::time::Duration::from_secs(60);

/// Writes to stderr, which may be gone: a background forwarder (`-f`)
/// outlives the terminal it started on, and `eprint!` would panic then.
fn say(text: &str) {
    use std::io::Write;
    let _ = std::io::stderr().write_all(text.as_bytes());
}

/// Reports that a forwarded connection could not be opened: once per target
/// and minute, so that a browser trying dozens of connections to a port that
/// does not answer does not flood the terminal. The line ends with `\r\n`,
/// as the terminal may be in raw mode for a session.
fn report_failure(target: &str, e: &anyhow::Error) {
    use std::time::Instant;
    static SHOWN: std::sync::OnceLock<Mutex<HashMap<String, Instant>>> = std::sync::OnceLock::new();
    let now = Instant::now();
    let show = {
        let mut shown = SHOWN.get_or_init(Default::default).lock().unwrap();
        shown.retain(|_, at| now.duration_since(*at) < QUIET_REPEATS);
        shown.insert(target.to_string(), now).is_none()
    };
    // Not with -q (LogLevel quiet/error).
    if show && tracing::enabled!(tracing::Level::WARN) {
        say(&format!("qsh: cannot forward to {target}: {e:#} (repeats are not shown for a minute)\r\n"));
    } else {
        debug!("forward to {target}: {e:#}");
    }
}

/// Opens a `DirectTcp` stream through the server.
pub async fn open_direct(conn: &Conn, host: &str, port: u16) -> Result<(SendHalf, RecvHalf)> {
    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, &Request::DirectTcp { host: host.to_string(), port }).await?;
    expect_ok(&mut recv).await?;
    Ok((send, recv))
}

/// Opens a stream to a Unix socket on the server.
async fn open_direct_local(conn: &Conn, path: &str) -> Result<(SendHalf, RecvHalf)> {
    if conn.server_version() < 6 {
        bail!("the server's qshd is too old for Unix socket forwarding");
    }
    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, &Request::DirectStreamLocal { path: path.to_string() }).await?;
    expect_ok(&mut recv).await?;
    Ok((send, recv))
}

/// Serves one local connection of a `-L`/`-D` forward through the server.
async fn serve_local<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(conn: Arc<Conn>, dest: Dest, mut sock: S, peer: String) {
    let result = match &dest {
        Dest::Tcp { host, port } => match open_direct(&conn, host, *port).await {
            Ok((send, recv)) => bridge_stream(sock, send, recv).await,
            Err(e) => return report_failure(&format!("{host}:{port}"), &e),
        },
        Dest::Unix(path) => match open_direct_local(&conn, path).await {
            Ok((send, recv)) => bridge_stream(sock, send, recv).await,
            Err(e) => return report_failure(path, &e),
        },
        Dest::Socks => {
            async {
                // A program that connects and never finishes the handshake
                // must not hold the connection forever.
                let req = tokio::time::timeout(SOCKS_HANDSHAKE, super::socks::accept(&mut sock))
                    .await
                    .map_err(|_| anyhow::anyhow!("no SOCKS request in time"))??;
                match open_direct(&conn, &req.host, req.port).await {
                    Ok((send, recv)) => {
                        req.reply(&mut sock, true).await?;
                        bridge_stream(sock, send, recv).await
                    }
                    Err(e) => {
                        let _ = req.reply(&mut sock, false).await;
                        Err(e.context(format!("{}:{}", req.host, req.port)))
                    }
                }
            }
            .await
        }
    };
    // Ends of open connections (resets included) are normal traffic.
    match result {
        Ok(()) => debug!("forward from {peer} closed"),
        Err(e) => debug!("forward from {peer}: {e:#}"),
    }
}

async fn bridge_stream<S: AsyncRead + AsyncWrite + Unpin>(sock: S, send: SendHalf, recv: RecvHalf) -> Result<()> {
    let (r, w) = tokio::io::split(sock);
    crate::transport::bridge(r, w, send, recv).await
}

/// Connects to a `-R` forward's destination here and relays the stream.
async fn serve_remote(dest: Dest, send: SendHalf, recv: RecvHalf, origin: String) {
    let result = match &dest {
        Dest::Tcp { host, port } => match TcpStream::connect((host.as_str(), *port)).await {
            Ok(tcp) => {
                let _ = tcp.set_nodelay(true);
                crate::transport::splice(tcp, send, recv).await
            }
            Err(e) => return report_failure(&format!("{host}:{port}"), &e.into()),
        },
        #[cfg(unix)]
        Dest::Unix(path) => match tokio::net::UnixStream::connect(path).await {
            Ok(sock) => bridge_stream(sock, send, recv).await,
            Err(e) => return report_failure(path, &e.into()),
        },
        #[cfg(not(unix))]
        Dest::Unix(path) => return report_failure(path, &anyhow::anyhow!("Unix sockets are not supported here")),
        // `-R port`: the connection speaks SOCKS; its target is reached from here.
        Dest::Socks => {
            async {
                let mut stream = tokio::io::join(recv, send);
                let req = tokio::time::timeout(SOCKS_HANDSHAKE, super::socks::accept(&mut stream))
                    .await
                    .map_err(|_| anyhow::anyhow!("no SOCKS request in time"))??;
                match TcpStream::connect((req.host.as_str(), req.port)).await {
                    Ok(tcp) => {
                        req.reply(&mut stream, true).await?;
                        let _ = tcp.set_nodelay(true);
                        let (recv, send) = stream.into_inner();
                        crate::transport::splice(tcp, send, recv).await
                    }
                    Err(e) => {
                        let _ = req.reply(&mut stream, false).await;
                        Err(anyhow::Error::from(e).context(format!("{}:{}", req.host, req.port)))
                    }
                }
            }
            .await
        }
    };
    if let Err(e) = result {
        debug!("remote forward from {origin}: {e:#}");
    }
}

/// Where connections the server opens go.
#[derive(Default)]
struct Routes {
    ports: HashMap<u16, Dest>,
    paths: HashMap<String, Dest>,
    agent: Option<Arc<PathBuf>>,
    x11: Option<Arc<super::x11::X11Auth>>,
}

/// One active forward.
struct Active {
    kind: char,
    fwd: Forward,
    /// Local listeners (`-L`, `-D`): their accept loops.
    tasks: Vec<AbortHandle>,
    /// `-R`: the request streams; closing them cancels the forward.
    _request: Option<(SendHalf, RecvHalf)>,
    /// `-R`: the port the server bound.
    bound: Option<u16>,
}

impl Drop for Active {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// The forwards of one connection.
pub struct Forwarder {
    conn: Arc<Conn>,
    /// `-g`: local forwards listen on all addresses by default.
    gateway: bool,
    active: Mutex<Vec<Active>>,
    routes: Arc<Mutex<Routes>>,
    dispatcher: Mutex<Option<AbortHandle>>,
    /// Agent and X11 forwarding requested (their streams are kept here).
    agent_request: Mutex<Option<(SendHalf, RecvHalf)>>,
    x11_request: Mutex<Option<(SendHalf, RecvHalf)>>,
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        if let Some(d) = self.dispatcher.lock().unwrap().take() {
            d.abort();
        }
    }
}

impl Forwarder {
    pub fn new(conn: Arc<Conn>, gateway: bool) -> Arc<Forwarder> {
        Arc::new(Forwarder {
            conn,
            gateway,
            active: Mutex::default(),
            routes: Arc::default(),
            dispatcher: Mutex::default(),
            agent_request: Mutex::default(),
            x11_request: Mutex::default(),
        })
    }

    /// `-L` (`kind` 'L') or `-D` ('D'): listens here.
    pub async fn local(&self, kind: char, fwd: Forward) -> Result<()> {
        let mut tasks = Vec::new();
        match &fwd.listen {
            Listen::Tcp { bind, port } => {
                for listener in bind_local(bind.as_deref(), *port, self.gateway).await? {
                    let (conn, dest) = (self.conn.clone(), fwd.dest.clone());
                    tasks.push(
                        tokio::spawn(async move {
                            while let Ok((tcp, peer)) = listener.accept().await {
                                let _ = tcp.set_nodelay(true);
                                tokio::spawn(serve_local(conn.clone(), dest.clone(), tcp, peer.to_string()));
                            }
                        })
                        .abort_handle(),
                    );
                }
            }
            #[cfg(unix)]
            Listen::Unix(path) => {
                let listener = bind_local_unix(path)?;
                let (conn, dest, path) = (self.conn.clone(), fwd.dest.clone(), path.clone());
                tasks.push(
                    tokio::spawn(async move {
                        while let Ok((sock, _)) = listener.accept().await {
                            tokio::spawn(serve_local(conn.clone(), dest.clone(), sock, path.clone()));
                        }
                    })
                    .abort_handle(),
                );
            }
            #[cfg(not(unix))]
            Listen::Unix(_) => bail!("Unix sockets are not supported here"),
        }
        self.active.lock().unwrap().push(Active { kind, fwd, tasks, _request: None, bound: None });
        Ok(())
    }

    /// `-R`: asks the server to listen. Returns the port it bound (TCP).
    pub async fn remote(&self, fwd: Forward) -> Result<Option<u16>> {
        if self.conn.is_shared() {
            bail!("remote forwards need a connection of their own (this one is shared)");
        }
        // Routes first: a connection may arrive right after the server listens.
        self.dispatch();
        let (mut send, mut recv) = self.conn.open_bi().await?;
        let bound = match &fwd.listen {
            Listen::Tcp { bind, port } => {
                // Like ssh: without an address, ask for loopback.
                let bind = bind.clone().unwrap_or_else(|| "localhost".into());
                write_msg(&mut send, &Request::RemoteForward { bind, port: *port }).await?;
                match expect_ok(&mut recv).await? {
                    Reply::Bound { port } => {
                        self.routes.lock().unwrap().ports.insert(port, fwd.dest.clone());
                        Some(port)
                    }
                    other => bail!("unexpected reply {other:?}"),
                }
            }
            Listen::Unix(path) => {
                if self.conn.server_version() < 6 {
                    bail!("the server's qshd is too old for Unix socket forwarding");
                }
                write_msg(&mut send, &Request::RemoteForwardStreamLocal { path: path.clone() }).await?;
                expect_ok(&mut recv).await?;
                self.routes.lock().unwrap().paths.insert(path.clone(), fwd.dest.clone());
                None
            }
        };
        self.active.lock().unwrap().push(Active { kind: 'R', fwd, tasks: Vec::new(), _request: Some((send, recv)), bound });
        Ok(bound)
    }

    /// `-A`: asks the server to offer the local agent at `path` to its
    /// sessions. Problems are warnings, as in ssh: the session works without.
    pub async fn agent(&self, path: PathBuf, quiet: bool) {
        if self.conn.server_version() < 4 {
            if !quiet {
                say("qsh: warning: the server's qshd is too old for agent forwarding (-A)\n");
            }
            return;
        }
        self.routes.lock().unwrap().agent = Some(Arc::new(path));
        self.dispatch();
        let attempt = async {
            let (mut send, mut recv) = self.conn.open_bi().await?;
            write_msg(&mut send, &Request::AgentForward).await?;
            expect_ok(&mut recv).await?;
            anyhow::Ok((send, recv))
        };
        match attempt.await {
            Ok(streams) => *self.agent_request.lock().unwrap() = Some(streams),
            Err(e) => {
                self.routes.lock().unwrap().agent = None;
                if !quiet {
                    say(&format!("qsh: warning: agent forwarding refused: {e:#}\n"));
                }
            }
        }
    }

    /// `-X`/`-Y`: asks the server for a display whose connections come to
    /// the local one. Problems are warnings, as for the agent.
    pub async fn x11(&self, auth: super::x11::X11Auth, quiet: bool) {
        if self.conn.server_version() < 6 {
            if !quiet {
                say("qsh: warning: the server's qshd is too old for X11 forwarding\n");
            }
            return;
        }
        let request = Request::X11Forward { proto: auth.proto.clone(), cookie: auth.fake_hex(), screen: auth.screen };
        self.routes.lock().unwrap().x11 = Some(Arc::new(auth));
        self.dispatch();
        let attempt = async {
            let (mut send, mut recv) = self.conn.open_bi().await?;
            write_msg(&mut send, &request).await?;
            expect_ok(&mut recv).await?;
            anyhow::Ok((send, recv))
        };
        match attempt.await {
            Ok(streams) => *self.x11_request.lock().unwrap() = Some(streams),
            Err(e) => {
                self.routes.lock().unwrap().x11 = None;
                if !quiet {
                    say(&format!("qsh: warning: X11 forwarding refused: {e:#}\n"));
                }
            }
        }
    }

    /// `-w`: a tunnel device here and one on the server (`units`: local,
    /// remote), with the packets between them.
    pub async fn tunnel(&self, ethernet: bool, units: (Option<u32>, Option<u32>)) -> Result<String> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            if self.conn.server_version() < 6 {
                bail!("the server's qshd is too old for tunnels (-w)");
            }
            let (dev, name) = crate::tunnel::open(ethernet, units.0)?;
            let (mut send, mut recv) = self.conn.open_bi().await?;
            write_msg(&mut send, &Request::Tunnel { ethernet, unit: units.1 }).await?;
            expect_ok(&mut recv).await?;
            let task = tokio::spawn(async move {
                if let Err(e) = crate::tunnel::relay(dev, send, recv).await {
                    debug!("tunnel: {e:#}");
                }
            });
            let fwd = Forward { listen: Listen::Unix(name.clone()), dest: Dest::Socks };
            self.active.lock().unwrap().push(Active { kind: 'w', fwd, tasks: vec![task.abort_handle()], _request: None, bound: None });
            Ok(name)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (ethernet, units);
            bail!("tunnel devices (-w) are not supported on this system")
        }
    }

    /// Cancels the `kind` forward listening at `listen` (`[bind:]port` or a
    /// path, as given when it was added). Returns whether there was one.
    pub fn cancel(&self, kind: char, listen: &str) -> Result<bool> {
        let parts = split_spec(listen)?;
        let wanted = parse_listen(&parts, listen)?;
        let mut active = self.active.lock().unwrap();
        let before = active.len();
        let mut routes = self.routes.lock().unwrap();
        active.retain(|a| {
            let same = a.kind == kind
                && match (&a.fwd.listen, &wanted) {
                    // `-KL 8080` also cancels `localhost:8080`, as in ssh.
                    (Listen::Tcp { bind, port }, Listen::Tcp { bind: b2, port: p2 }) => {
                        (port == p2 || a.bound == Some(*p2)) && (b2.is_none() || bind == b2)
                    }
                    (Listen::Unix(p), Listen::Unix(p2)) => p == p2,
                    _ => false,
                };
            if same {
                match &a.fwd.listen {
                    Listen::Tcp { .. } => {
                        if let Some(p) = a.bound {
                            routes.ports.remove(&p);
                        }
                    }
                    Listen::Unix(p) => {
                        routes.paths.remove(p);
                    }
                }
            }
            !same
        });
        Ok(active.len() != before)
    }

    /// Adds or cancels a forward given as on the command line (`-O forward`,
    /// `-O cancel`); a cancel may give the whole spec or just where it listens.
    pub async fn request(&self, kind: char, spec: &str, cancel: bool) -> Result<String> {
        let parsed = match kind {
            'L' => Forward::parse(spec),
            'R' => Forward::parse_remote(spec),
            'D' => Forward::parse_dynamic(spec),
            _ => bail!("unknown forward kind {kind}"),
        };
        if cancel {
            let listen = match &parsed {
                Ok(f) => match &f.listen {
                    Listen::Tcp { bind: Some(b), port } if b.contains(':') => format!("[{b}]:{port}"),
                    Listen::Tcp { bind: Some(b), port } => format!("{b}:{port}"),
                    Listen::Tcp { bind: None, port } => port.to_string(),
                    Listen::Unix(p) => p.clone(),
                },
                Err(_) => spec.to_string(),
            };
            return match self.cancel(kind, &listen)? {
                true => Ok(String::new()),
                false => bail!("no such forward: -{kind} {spec}"),
            };
        }
        let fwd = parsed?;
        match kind {
            'R' => Ok(self.remote(fwd).await?.filter(|_| spec.split(':').any(|p| p == "0")).map(|p| p.to_string()).unwrap_or_default()),
            _ => self.local(kind, fwd).await.map(|()| String::new()),
        }
    }

    /// The active forwards, as `-L spec` lines (`~#`).
    pub fn list(&self) -> Vec<String> {
        self.active
            .lock()
            .unwrap()
            .iter()
            .map(|a| match (a.kind, a.bound) {
                ('R', Some(p)) if matches!(a.fwd.listen, Listen::Tcp { port: 0, .. }) => format!("-R {} (port {p})", a.fwd.describe()),
                (k, _) => format!("-{k} {}", a.fwd.describe()),
            })
            .collect()
    }

    /// Starts serving the streams the server opens (`-R` connections, the
    /// agent), once.
    fn dispatch(&self) {
        let mut slot = self.dispatcher.lock().unwrap();
        if slot.is_some() {
            return;
        }
        let (conn, routes) = (self.conn.clone(), self.routes.clone());
        let task = tokio::spawn(async move {
            while let Some((send, mut recv)) = conn.accept_bi().await {
                let routes = routes.clone();
                tokio::spawn(async move {
                    let opened = match read_msg(&mut recv).await {
                        Ok(o) => o,
                        Err(_) => return,
                    };
                    // Looked up first: the lock must not be held across an await.
                    enum Next {
                        Remote(Dest, String),
                        Agent(Arc<PathBuf>),
                        X11(Arc<super::x11::X11Auth>, String),
                    }
                    let next = {
                        let r = routes.lock().unwrap();
                        match opened {
                            Opened::Forwarded { port, origin } => r.ports.get(&port).cloned().map(|d| Next::Remote(d, origin)),
                            Opened::ForwardedStreamLocal { path } => r.paths.get(&path).cloned().map(|d| Next::Remote(d, path)),
                            // Only if we asked for it: a server cannot reach our agent or display on its own.
                            Opened::Agent => r.agent.clone().map(Next::Agent),
                            Opened::X11 { origin } => r.x11.clone().map(|a| Next::X11(a, origin)),
                        }
                    };
                    match next {
                        Some(Next::Remote(dest, origin)) => serve_remote(dest, send, recv, origin).await,
                        Some(Next::Agent(path)) => match crate::agent::connect_raw(path.as_path()).await {
                            Ok(sock) => {
                                let (ar, aw) = tokio::io::split(sock);
                                let _ = crate::transport::bridge(ar, aw, send, recv).await;
                            }
                            Err(e) => warn!("forwarded agent: {e}"),
                        },
                        Some(Next::X11(auth, origin)) => {
                            if let Err(e) = super::x11::serve(&auth, send, recv).await {
                                debug!("X11 connection from {origin}: {e:#}");
                            }
                        }
                        None => {}
                    }
                });
            }
        });
        *slot = Some(task.abort_handle());
    }
}

/// A local Unix socket listener (`-L /path:...`), private to this user.
#[cfg(unix)]
fn bind_local_unix(path: &str) -> Result<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    let l = tokio::net::UnixListener::bind(path).with_context(|| format!("cannot listen on {path}"))?;
    // Like ssh's default StreamLocalBindMask 0177.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

/// `-W host:port`: connects stdin/stdout to `host:port` through the server.
pub async fn stdio(conn: &Conn, spec: &str) -> Result<()> {
    let parts = split_spec(spec)?;
    let (send, recv) = match parts.as_slice() {
        [path] if is_path(path) => open_direct_local(conn, path).await?,
        [host, port] => open_direct(conn, host, parse_port(port, spec)?).await?,
        _ => bail!("-W expects host:port or a socket path, got {spec:?}"),
    };
    crate::transport::bridge(tokio::io::stdin(), tokio::io::stdout(), send, recv).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(host: &str, port: u16) -> Dest {
        Dest::Tcp { host: host.into(), port }
    }

    #[test]
    fn parse_specs() {
        let f = Forward::parse("8080:localhost:80").unwrap();
        assert_eq!(f, Forward { listen: Listen::Tcp { bind: None, port: 8080 }, dest: tcp("localhost", 80) });
        let f = Forward::parse("0.0.0.0:8080:db.internal:5432").unwrap();
        assert_eq!(f.listen, Listen::Tcp { bind: Some("0.0.0.0".into()), port: 8080 });
        assert_eq!(f.dest, tcp("db.internal", 5432));
        let f = Forward::parse("[::1]:8080:[fe80::1]:22").unwrap();
        assert_eq!((f.listen, f.dest), (Listen::Tcp { bind: Some("::1".into()), port: 8080 }, tcp("fe80::1", 22)));
        assert!(Forward::parse("8080:host").is_err());
        assert!(Forward::parse("x:host:80").is_err());
        assert_eq!(Forward::parse_dynamic("1080").unwrap().listen, Listen::Tcp { bind: None, port: 1080 });
        assert_eq!(Forward::parse_dynamic("*:1080").unwrap().listen, Listen::Tcp { bind: Some("*".into()), port: 1080 });
        assert!(Forward::parse_dynamic("a:b:c").is_err());
    }

    #[test]
    fn socket_and_socks_specs() {
        let f = Forward::parse("8080:/run/app.sock").unwrap();
        assert_eq!((f.listen, f.dest), (Listen::Tcp { bind: None, port: 8080 }, Dest::Unix("/run/app.sock".into())));
        let f = Forward::parse("/tmp/l.sock:db:5432").unwrap();
        assert_eq!((f.listen, f.dest), (Listen::Unix("/tmp/l.sock".into()), tcp("db", 5432)));
        let f = Forward::parse("/tmp/a.sock:/run/b.sock").unwrap();
        assert_eq!((f.listen, f.dest), (Listen::Unix("/tmp/a.sock".into()), Dest::Unix("/run/b.sock".into())));
        let f = Forward::parse("localhost:8080:/run/app.sock").unwrap();
        assert_eq!(f.listen, Listen::Tcp { bind: Some("localhost".into()), port: 8080 });
        assert_eq!(Forward::parse_remote("8080").unwrap().dest, Dest::Socks);
        assert_eq!(Forward::parse_remote("0.0.0.0:8080").unwrap().dest, Dest::Socks);
        assert_eq!(Forward::parse_remote("8080:localhost:80").unwrap().dest, tcp("localhost", 80));
        assert!(Forward::parse("8080").is_err(), "-L needs a destination");
        assert_eq!(Forward::parse("/a:/b").unwrap().describe(), "/a:/b");
        assert_eq!(Forward::parse_remote("[::1]:9").unwrap().describe(), "[::1]:9");
    }

    #[tokio::test]
    async fn default_bind_is_loopback_only() {
        let ls = bind_local(None, 0, false).await.unwrap();
        assert!(ls.iter().all(|l| l.local_addr().unwrap().ip().is_loopback()));
        let ls = bind_local(None, 0, true).await.unwrap();
        assert!(ls.iter().all(|l| l.local_addr().unwrap().ip().is_unspecified()));
    }
}
