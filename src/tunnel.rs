//! Tunnel devices (`qsh -w`), like ssh's: a TUN (point-to-point, IP
//! packets) or TAP (ethernet frames) device on each side, and the packets
//! between them on one stream, each with a 4-byte length in front. Both
//! sides need the right to create network devices (root). The devices are
//! created up but without addresses; configuring them is left to the user,
//! as with ssh.

use anyhow::{Context, Result};

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use device::{device_name, open, relay};

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod device {
    use std::sync::Arc;

    use anyhow::{bail, Context, Result};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::transport::{RecvHalf, SendHalf};

    /// Largest packet carried (a jumbo frame and then some).
    const MAX_PACKET: usize = 65536;

    /// The name of device number `unit` (`tun3`, `tap3`, `utun3`).
    pub fn device_name(ethernet: bool, unit: u32) -> String {
        let prefix = if cfg!(target_os = "macos") {
            "utun"
        } else if ethernet {
            "tap"
        } else {
            "tun"
        };
        format!("{prefix}{unit}")
    }

    /// `unit`: the device number (`tun3`), or `None` for the next free one.
    pub fn open(ethernet: bool, unit: Option<u32>) -> Result<(tun_rs::AsyncDevice, String)> {
        let mut b = tun_rs::DeviceBuilder::new().layer(if ethernet {
            tun_rs::Layer::L2
        } else {
            tun_rs::Layer::L3
        });
        if let Some(u) = unit {
            b = b.name(device_name(ethernet, u));
        }
        let dev = b.build_async().context("cannot create the tunnel device")?;
        let name = dev.name().unwrap_or_default();
        Ok((dev, name))
    }

    /// Carries packets between `dev` and the stream until either ends.
    pub async fn relay(
        dev: tun_rs::AsyncDevice,
        mut send: SendHalf,
        mut recv: RecvHalf,
    ) -> Result<()> {
        let dev = Arc::new(dev);
        let up = {
            let dev = dev.clone();
            async move {
                // The length and the packet in one write, sent right away.
                let mut buf = vec![0u8; 4 + MAX_PACKET];
                loop {
                    let n = dev.recv(&mut buf[4..]).await?;
                    if n == 0 {
                        continue;
                    }
                    buf[..4].copy_from_slice(&(n as u32).to_be_bytes());
                    send.write_all(&buf[..4 + n]).await?;
                    send.flush().await?;
                }
                #[allow(unreachable_code)]
                anyhow::Ok(())
            }
        };
        let down = async move {
            let mut buf = vec![0u8; MAX_PACKET];
            loop {
                let len = match recv.read_u32().await {
                    Ok(n) => n as usize,
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return anyhow::Ok(())
                    }
                    Err(e) => return Err(e.into()),
                };
                if len > MAX_PACKET {
                    bail!("tunnel packet of {len} bytes");
                }
                if len == 0 {
                    continue;
                }
                recv.read_exact(&mut buf[..len]).await?;
                // A packet the device does not take (down, wrong family) is dropped, as by a network.
                let _ = dev.send(&buf[..len]).await;
            }
        };
        tokio::select! {
            r = up => r,
            r = down => r,
        }
    }
}

/// `-w`'s and `TunnelDevice`'s `local[:remote]` with `any` or numbers.
pub fn parse_units(spec: &str) -> Result<(Option<u32>, Option<u32>)> {
    let unit = |s: &str| -> Result<Option<u32>> {
        match s {
            "" | "any" => Ok(None),
            n => n
                .parse()
                .map(Some)
                .with_context(|| format!("bad tunnel device {n:?} (a number or any)")),
        }
    };
    match spec.split_once(':') {
        Some((l, r)) => Ok((unit(l)?, unit(r)?)),
        None => Ok((unit(spec)?, None)),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn units() {
        assert_eq!(super::parse_units("0:1").unwrap(), (Some(0), Some(1)));
        assert_eq!(super::parse_units("any").unwrap(), (None, None));
        assert_eq!(super::parse_units("any:5").unwrap(), (None, Some(5)));
        assert!(super::parse_units("x").is_err());
    }
}
