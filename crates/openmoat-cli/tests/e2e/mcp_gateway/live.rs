//! Drive a proxy session a line at a time.

use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Child, ChildStdin, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use serde_json::Value;

use super::Gateway;

/// A proxy session driven a line at a time.
pub(super) struct Live {
    pub(super) child: Child,
    pub(super) stdin: Option<ChildStdin>,
    lines: Receiver<String>,
}

impl Live {
    pub(super) fn start(gw: &Gateway, mode: &str) -> Self {
        let mut child = gw
            .proxy(mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let out = BufReader::new(child.stdout.take().unwrap());
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in out.lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            lines,
        }
    }

    /// Send `line` and wait for the answer to `id`.
    pub(super) fn ask(&mut self, line: &str, id: u64) -> Value {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
        loop {
            let got = self
                .lines
                .recv_timeout(Duration::from_secs(20))
                .expect("an answer");
            if let Ok(message) = serde_json::from_str::<Value>(&got)
                && message["id"] == id
            {
                return message;
            }
        }
    }

    pub(super) fn end(mut self) {
        drop(self.stdin.take());
        let _ = self.child.wait();
    }
}
