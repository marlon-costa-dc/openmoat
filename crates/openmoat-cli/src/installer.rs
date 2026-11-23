//! The control plane the release was built for (ADR-104).
//!
//! `openmoat init` keeps its own state person-owned: an agent that can re-pin
//! can grant itself anything, so a re-pin over an existing lock is refused to
//! any process that descends from an agent (`terminal/ancestry.rs`). A host
//! whose agents are all managed by one local control plane needs that plane to
//! own the lifecycle instead of a terminal.
//!
//! The release build embeds the control plane's launcher path and its SHA-256
//! (`OPENMOAT_INSTALLER_ANCHOR`, `"<absolute path> <sha256>"`); a build without
//! it disables the capability. A request is accepted only when the anchored
//! file is an ancestor of this process, executed as `<interpreter> <path> …`,
//! and the file's bytes still hash to the anchor. Every other process is
//! refused, including one detached from an agent: this is an identity check on
//! the caller, not the parent-process escape the threat model documents.

/// `"<absolute path> <sha256>"`; empty when the build has no control plane.
const ANCHOR: &str = match option_env!("OPENMOAT_INSTALLER_ANCHOR") {
    Some(value) => value,
    None => "",
};

/// Split an anchor into its path and digest; `None` for an empty or malformed
/// one. The path may hold spaces, so the digest is cut from the right.
fn parse_anchor(raw: &str) -> Option<(&str, &str)> {
    let (path, digest) = raw.rsplit_once(' ')?;
    if path.is_empty()
        || !path.starts_with('/')
        || digest.len() != 64
        || !digest.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    Some((path, digest))
}

/// Whether one process's argument vector runs the anchored launcher: the
/// script is the first argument, as a console script's shebang hands it over
/// (`<interpreter> <script> …`).
fn runs_script(args: &[Vec<u8>], path: &str) -> bool {
    args.get(1).is_some_and(|arg| arg == path.as_bytes())
}

#[cfg(target_os = "linux")]
fn cmdline(pid: u32) -> Option<Vec<Vec<u8>>> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    Some(
        raw.split(|byte| *byte == 0)
            .filter(|word| !word.is_empty())
            .map(<[u8]>::to_vec)
            .collect(),
    )
}

#[cfg(target_os = "linux")]
fn parent_of(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:")?.trim().parse().ok())
}

/// The commands the declared control plane owns: installing the policy and
/// hooks, accepting its own MCP definitions and writing the sandboxes the
/// policy produces. Every other person-only command stays person-only.
const LIFECYCLE: &[&str] = &[
    "openmoat init",
    "openmoat mcp accept",
    "openmoat sandbox sync",
];

/// Whether the declared control plane may run `command` unattended.
pub(crate) fn authorized_for(command: &str) -> bool {
    !command.contains("--managed")
        && LIFECYCLE
            .iter()
            .any(|allowed| command == *allowed || command.starts_with(&format!("{allowed} ")))
        && authorized()
}

/// Whether this process was started by the anchored control plane.
#[cfg(target_os = "linux")]
pub(super) fn authorized() -> bool {
    let Some((path, digest)) = parse_anchor(ANCHOR) else {
        return false;
    };
    let mut pid = std::os::unix::process::parent_id();
    for _ in 0..16 {
        if pid <= 1 {
            return false;
        }
        if cmdline(pid).is_some_and(|args| runs_script(&args, path)) {
            return std::fs::read(path)
                .is_ok_and(|bytes| crate::integrity::sha256_hex(&bytes) == digest);
        }
        match parent_of(pid) {
            Some(next) if next != pid => pid = next,
            _ => return false,
        }
    }
    false
}

/// The capability is Linux-only for now; every other platform keeps the
/// person-only rule.
#[cfg(not(target_os = "linux"))]
pub(super) fn authorized() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::{parse_anchor, runs_script};

    const DIGEST: &str = "82213f68566ac8d1c52f9c034cfad17fe5531eb618bb820bbaef18b537358212";

    #[test]
    fn an_anchor_needs_an_absolute_path_and_a_sha256() {
        assert_eq!(
            parse_anchor(&format!("/home/me/ai-hub {DIGEST}")),
            Some(("/home/me/ai-hub", DIGEST))
        );
        assert_eq!(parse_anchor(""), None);
        assert_eq!(parse_anchor("/home/me/ai-hub"), None);
        assert_eq!(parse_anchor(&format!("ai-hub {DIGEST}")), None);
        assert_eq!(parse_anchor("/home/me/ai-hub nothex"), None);
    }

    #[test]
    fn the_anchor_is_the_script_the_interpreter_runs() {
        let args = vec![b"/venv/bin/python".to_vec(), b"/home/me/ai-hub".to_vec()];
        assert!(runs_script(&args, "/home/me/ai-hub"));
        assert!(!runs_script(&args, "/home/me/other"));
        let shell = vec![b"sh".to_vec(), b"-c".to_vec()];
        assert!(!runs_script(&shell, "/home/me/ai-hub"));
    }
}
