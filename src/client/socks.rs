//! Minimal SOCKS server side for `-D`: SOCKS5 (no authentication, CONNECT)
//! and SOCKS4/4a (CONNECT), like OpenSSH's dynamic forwarding.

use anyhow::{bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, PartialEq)]
pub struct Request {
    pub host: String,
    pub port: u16,
    version: u8,
}

async fn read_until_nul<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let b = r.read_u8().await?;
        if b == 0 {
            return Ok(out);
        }
        if out.len() >= 255 {
            bail!("SOCKS4 field too long");
        }
        out.push(b);
    }
}

/// Reads a client's CONNECT request.
pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> Result<Request> {
    match s.read_u8().await? {
        5 => {
            let n = s.read_u8().await? as usize;
            let mut methods = vec![0u8; n];
            s.read_exact(&mut methods).await?;
            if !methods.contains(&0) {
                s.write_all(&[5, 0xff]).await?;
                bail!("SOCKS5 client offers no 'no authentication' method");
            }
            s.write_all(&[5, 0]).await?;
            let mut head = [0u8; 4];
            s.read_exact(&mut head).await?;
            if head[0] != 5 || head[1] != 1 {
                // 0x07: command not supported (only CONNECT is).
                s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                bail!("unsupported SOCKS5 command {}", head[1]);
            }
            let host = match head[3] {
                1 => {
                    let mut ip = [0u8; 4];
                    s.read_exact(&mut ip).await?;
                    std::net::Ipv4Addr::from(ip).to_string()
                }
                3 => {
                    let len = s.read_u8().await? as usize;
                    let mut name = vec![0u8; len];
                    s.read_exact(&mut name).await?;
                    String::from_utf8(name)?
                }
                4 => {
                    let mut ip = [0u8; 16];
                    s.read_exact(&mut ip).await?;
                    std::net::Ipv6Addr::from(ip).to_string()
                }
                t => bail!("unsupported SOCKS5 address type {t}"),
            };
            let port = s.read_u16().await?;
            Ok(Request { host, port, version: 5 })
        }
        4 => {
            let cmd = s.read_u8().await?;
            let port = s.read_u16().await?;
            let mut ip = [0u8; 4];
            s.read_exact(&mut ip).await?;
            let _user = read_until_nul(s).await?;
            if cmd != 1 {
                s.write_all(&[0, 0x5b, 0, 0, 0, 0, 0, 0]).await?;
                bail!("unsupported SOCKS4 command {cmd}");
            }
            // SOCKS4a: 0.0.0.x (x != 0) means a host name follows.
            let host = if ip[..3] == [0, 0, 0] && ip[3] != 0 {
                String::from_utf8(read_until_nul(s).await?)?
            } else {
                std::net::Ipv4Addr::from(ip).to_string()
            };
            Ok(Request { host, port, version: 4 })
        }
        v => bail!("unsupported SOCKS version {v}"),
    }
}

impl Request {
    /// Tells the client whether the connection was made.
    pub async fn reply<S: AsyncWrite + Unpin>(&self, s: &mut S, ok: bool) -> Result<()> {
        if self.version == 5 {
            // 0x05: connection refused.
            s.write_all(&[5, if ok { 0 } else { 5 }, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        } else {
            s.write_all(&[0, if ok { 0x5a } else { 0x5b }, 0, 0, 0, 0, 0, 0]).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run(input: &[u8]) -> (Result<Request>, Vec<u8>) {
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(input).await.unwrap();
        let req = accept(&mut server).await;
        drop(server);
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        (req, out)
    }

    #[tokio::test]
    async fn socks5_domain_and_ipv6() {
        let mut msg = vec![5, 1, 0, 5, 1, 0, 3, 11];
        msg.extend(b"example.com");
        msg.extend(443u16.to_be_bytes());
        let (req, out) = run(&msg).await;
        assert_eq!(req.unwrap(), Request { host: "example.com".into(), port: 443, version: 5 });
        assert_eq!(out, [5, 0]);
        let mut msg = vec![5, 1, 0, 5, 1, 0, 4];
        msg.extend(std::net::Ipv6Addr::LOCALHOST.octets());
        msg.extend(22u16.to_be_bytes());
        assert_eq!(run(&msg).await.0.unwrap().host, "::1");
    }

    #[tokio::test]
    async fn socks4a_and_rejections() {
        let mut msg = vec![4, 1];
        msg.extend(80u16.to_be_bytes());
        msg.extend([0, 0, 0, 1]);
        msg.extend(b"user\0example.org\0");
        assert_eq!(run(&msg).await.0.unwrap(), Request { host: "example.org".into(), port: 80, version: 4 });
        // Only "no authentication" is offered by us; BIND/UDP are refused.
        let (req, out) = run(&[5, 1, 2]).await;
        assert!(req.is_err());
        assert_eq!(out, [5, 0xff]);
        let (req, _) = run(&[5, 1, 0, 5, 2, 0, 1, 1, 2, 3, 4, 0, 80]).await;
        assert!(req.is_err());
        assert!(run(&[9]).await.0.is_err());
    }
}
