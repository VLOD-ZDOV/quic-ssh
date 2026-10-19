//! Sessions that outlive the connection need a terminal qshd keeps open
//! on its own (Unix PTYs): not on Windows, where a session ends with it.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::watch;

use super::exec::Session;
use super::users::User;
use crate::authkeys::Restrictions;
use crate::proto::{write_msg, Reply};
use crate::transport::{RecvHalf, SendHalf};

pub const GONE: &str = "the session is gone (it ended or timed out)";

pub struct Sessions;

impl Sessions {
    pub fn new(_timeout: Duration) -> Sessions {
        Sessions
    }

    pub fn enabled(&self) -> bool {
        false
    }

    pub fn owns(&self, _token: &[u8], _uid: u32) -> bool {
        false
    }

    pub async fn start(
        self: &Arc<Self>,
        mut send: SendHalf,
        _recv: RecvHalf,
        _user: &User,
        _restrictions: &Restrictions,
        _session: Session,
        _closed: watch::Receiver<bool>,
    ) -> Result<()> {
        write_msg(&mut send, &Reply::Err("sessions that survive a lost connection are not available on Windows".into())).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn resume(
        self: &Arc<Self>,
        mut send: SendHalf,
        _recv: RecvHalf,
        _user: &User,
        _restrictions: &Restrictions,
        _token: &[u8],
        _received: u64,
        _closed: watch::Receiver<bool>,
    ) -> Result<()> {
        write_msg(&mut send, &Reply::Err(GONE.into())).await
    }
}
