//! `moat environment refresh`: record the machine's search path, re-pin the lock.
//!
//! The snapshot `~/.moat/environment.json` records where the common programs
//! lived when the machine was set up; every shell command is resolved through
//! it. A stale snapshot denies normal work in every session: a tool installed
//! elsewhere, a virtualenv's interpreter, or a distribution's second spelling
//! of the same file. The declared control plane records the one it renders,
//! and a person at a terminal records the one in front of them.

use std::path::Path;

use anyhow::{Result, bail};

use crate::cli::{EnvironmentArgs, EnvironmentCommand};
use crate::environment::Snapshot;
use crate::exit::Code;
use crate::home::Home;
use crate::integrity::{self, HookPins};

pub fn run(args: &EnvironmentArgs) -> Result<Code> {
    match args.command {
        EnvironmentCommand::Refresh => refresh(),
    }
}

/// Record this process's `PATH` as the machine's snapshot and re-pin the lock.
///
/// Why: only the control plane the release was built for, or a person at a
/// terminal, may change what the kernel trusts. An agent that could record its
/// own `PATH` would pin a project's virtualenv as the machine's interpreter,
/// which denies every other project.
fn refresh() -> Result<Code> {
    if !crate::terminal::interactive() && !crate::installer::authorized() {
        bail!(
            "`openmoat environment refresh` must be run by the control plane this \
             release was built for, or by a person at a terminal"
        );
    }
    let home = Home::locate()?;
    let verified = integrity::check(&home)?;
    if let Some(deny) = verified.checked.deny {
        bail!(
            "the policy lock does not hold, so the search path is not recorded: {}",
            deny.reasons.join("; ")
        );
    }
    let snapshot = Snapshot::capture();
    if snapshot.programs.is_empty() {
        bail!(
            "this shell's PATH finds none of the programs OpenMoat pins, so there is no \
             search path to record; run it from a normal shell"
        );
    }
    snapshot.save(&verified.home.environment_path())?;
    integrity::repin(
        &verified.home,
        Path::new(&verified.lock.binary),
        HookPins::Keep,
    )?;
    println!(
        "✔ environment      {} ({} dirs, {} programs pinned)",
        verified.home.environment_path().display(),
        snapshot.path.len(),
        snapshot.programs.len()
    );
    Ok(Code::Ok)
}
