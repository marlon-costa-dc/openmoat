//! Bound the shutdown of a stdio upstream after either pipe stops.

use std::io;
use std::process::{Child, ExitStatus};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};

#[cfg(not(unix))]
mod other;
#[cfg(unix)]
mod unix;

#[cfg(not(unix))]
use other as platform;
#[cfg(unix)]
use unix as platform;

pub(super) use platform::own;

const GRACE: Duration = Duration::from_secs(1);
const REPLY_GRACE: Duration = Duration::from_secs(5);

pub(super) enum Pump {
    Host {
        result: Result<()>,
        pending_replies: bool,
    },
    Server(Result<bool>),
}

/// Reap the upstream whether the byte pumps finish cleanly or time out.
pub(super) fn supervise(mut child: Child, finished: &Receiver<Pump>) -> Result<ExitStatus> {
    let result = drain(finished)
        .and_then(|pending_replies| wait(&mut child).map(|status| (status, pending_replies)));
    if result.is_err() {
        platform::stop(&mut child);
        child.wait().context("reaping the stopped MCP server")?;
    }
    let (status, pending_replies) = result?;
    if status.success() && pending_replies {
        bail!("MCP server closed its output with unanswered requests");
    }
    Ok(status)
}

fn drain(finished: &Receiver<Pump>) -> Result<bool> {
    let mut next = finished
        .recv()
        .context("MCP relay stopped without reporting its result")?;
    loop {
        let grace = match next {
            Pump::Server(result) => return result,
            Pump::Host {
                result,
                pending_replies,
            } => {
                result?;
                if pending_replies { REPLY_GRACE } else { GRACE }
            }
        };
        next = match finished.recv_timeout(grace) {
            Ok(event) => event,
            Err(RecvTimeoutError::Timeout) => {
                bail!("MCP server did not close its output after client EOF")
            }
            Err(error) => {
                return Err(error).context("MCP server pump stopped without reporting its result");
            }
        };
    }
}

fn wait(child: &mut Child) -> Result<ExitStatus> {
    let deadline = Instant::now() + GRACE;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => bail!("MCP server did not exit after closing its output"),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) => return Err(error).context("waiting for the MCP server"),
        }
    }
}
