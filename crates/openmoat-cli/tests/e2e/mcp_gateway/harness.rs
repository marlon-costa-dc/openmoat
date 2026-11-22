//! Installed MCP test server, hook decisions and recorded messages.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use openmoat_hosts::Host;
use serde_json::{Value, json};

use crate::common::{OK, Sandbox, output, stdout, text};
use crate::hosts::dir_of;

/// Every place a reader may end a line (as in `src/mcp/relay/tests/gaps.rs`).
const LINE_BREAKS: [char; 5] = ['\n', '\r', '\u{85}', '\u{2028}', '\u{2029}'];

fn server_script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/e2e/mcp_gateway/recording_server.py")
}

/// An installed home whose MCP server `docs` has had its tools accepted.
pub(super) struct Gateway {
    pub(super) sb: Sandbox,
    record: PathBuf,
    host: Option<&'static str>,
}

impl Gateway {
    pub(super) fn new() -> Self {
        Self::for_host(None)
    }

    pub(super) fn for_host(host: Option<&'static str>) -> Self {
        let sb = Sandbox::installed(&[&dir_of(Host::ClaudeCode)]);
        let record = sb.home.join("record.jsonl");
        let gateway = Self { sb, record, host };
        // `openmoat mcp proxy` starts only a definition a person accepted
        // (ADR-049): one per mode, each starting the proxy as `docs`.
        for mode in [
            "answer", "silent", "rug", "inject", "fail", "instruct", "sample", "stubborn",
        ] {
            let line = gateway.proxy_line(mode);
            let args: Vec<&str> = line.iter().map(String::as_str).collect();
            gateway.sb.define_wrapped(&format!("docs-{mode}"), &args);
        }
        gateway.sb.accept_mcp();
        let listed = gateway.session("answer", &[list(1)]);
        assert!(
            listed.contains(r#""tools":[]"#),
            "a new server is held: {listed}"
        );
        let accepted = gateway.sb.moat_approving(&["mcp", "accept", "docs"]);
        assert_eq!(accepted.status.code(), Some(OK), "{}", text(&accepted));
        let listed = gateway.session("answer", &[list(1)]);
        assert!(listed.contains("Accepted."), "{listed}");
        gateway.forget();
        gateway
    }

    /// What follows `mcp proxy` to start the server in `mode`.
    fn proxy_line(&self, mode: &str) -> Vec<String> {
        let script = server_script().to_string_lossy().into_owned();
        let record = self.record.to_string_lossy().into_owned();
        let mut args = vec!["--server", "docs"];
        if let Some(host) = self.host {
            args.extend(["--host", host]);
        }
        args.extend(["--", "python3", &script, &record, mode]);
        args.into_iter().map(str::to_owned).collect()
    }

    pub(super) fn proxy(&self, mode: &str) -> Command {
        let mut command = self.sb.command();
        command.args(["mcp", "proxy"]).args(self.proxy_line(mode));
        command
    }

    /// One session: `lines` from the host, all at once; what the host got.
    pub(super) fn session(&self, mode: &str, lines: &[String]) -> String {
        let out = self.run(mode, lines);
        assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
        stdout(&out)
    }

    pub(super) fn run(&self, mode: &str, lines: &[String]) -> Output {
        let input: String = lines.iter().flat_map(|l| [l.as_str(), "\n"]).collect();
        output(&mut self.proxy(mode), Some(&input))
    }

    /// What reached the server so far.
    pub(super) fn recorded(&self) -> String {
        std::fs::read_to_string(&self.record).unwrap_or_default()
    }

    /// The messages that reached the server, each piece cut at every line
    /// break and read as one whole message.
    pub(super) fn received(&self) -> Vec<Value> {
        self.recorded()
            .split(LINE_BREAKS)
            .filter(|p| !p.trim().is_empty())
            .map(|p| serde_json::from_str(p).unwrap_or_else(|e| panic!("{e}: {p:?}")))
            .collect()
    }

    /// The tool calls that reached the server.
    pub(super) fn calls(&self) -> Vec<Value> {
        self.received()
            .into_iter()
            .flat_map(|m| match m {
                Value::Array(batch) => batch,
                one => vec![one],
            })
            .filter(|m| m["method"] == "tools/call")
            .collect()
    }

    pub(super) fn forget(&self) {
        let _ = std::fs::remove_file(&self.record);
    }

    /// The verdict `host`'s hook (Claude Code's or Codex's) gives
    /// `mcp__docs__<tool>` with `arguments` in `session`.
    pub(super) fn hook(&self, host: &str, session: &str, tool: &str, arguments: &Value) -> String {
        self.hook_in(host, session, tool, arguments, "default")
    }

    /// [`Gateway::hook`] in Claude Code permission mode `mode`.
    pub(super) fn hook_in(
        &self,
        host: &str,
        session: &str,
        tool: &str,
        arguments: &Value,
        mode: &str,
    ) -> String {
        let payload = json!({
            "session_id": session, "cwd": self.sb.project().to_string_lossy(),
            "hook_event_name": "PreToolUse", "tool_name": format!("mcp__docs__{tool}"),
            "tool_input": arguments, "tool_use_id": format!("{session}-{tool}"),
            "permission_mode": mode
        });
        let out = self.sb.guard(host, &payload.to_string());
        let answer: Value = serde_json::from_str(stdout(&out).trim()).unwrap_or(Value::Null);
        answer["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .unwrap_or(if out.status.code() == Some(2) {
                "deny"
            } else {
                "defer"
            })
            .to_owned()
    }

    /// The audit rows the proxy left.
    pub(super) fn proxy_rows(&self) -> Vec<Value> {
        let out = self.sb.moat(&["audit", "export"]);
        assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
        stdout(&out)
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .filter(|row| row["host"] == "mcp-proxy")
            .collect()
    }
}

pub(super) fn list(id: u64) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/list"}).to_string()
}
