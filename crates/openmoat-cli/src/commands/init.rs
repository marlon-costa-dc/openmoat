//! `moat init`: create the state directory, default policy, audit log and host hooks.
//!
//! What a person sees: a line per agent found with what it would get and the
//! question (`ask.rs`), then the agents protected, the steps left and how to
//! undo (`summary.rs`). Each file written, the backups and the lock are shown
//! with `--verbose` (and in a dry run).

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use openmoat_core::{DEFAULT_POLICY, Policy};
use openmoat_hosts::Host;
use serde::Serialize;

use crate::cli::{Format, InitArgs};
use crate::environment::Snapshot;
use crate::exit::Code;
use crate::home::Home;
use crate::install::{HookLayout, HostConfig, Outcome, Recorded};
use crate::installer;
use crate::integrity;
use crate::render::Deferred;
use crate::report::Style;
use crate::sandbox::{self, Plan};

mod ask;
mod managed;
pub(super) mod mcp;
mod preview;
mod refuse;
mod summary;
#[cfg(test)]
mod tests;
mod unattended;

use refuse::{refuse_repin, refuse_writable_binary};

pub fn run(args: &InitArgs) -> Result<Code> {
    let dry_run = args.dry_run;
    let json = args.format == Format::Json;
    let hooks_only = args.managed.hooks_only;
    // A dry run is a list of what would be written: every line of it shows.
    let verbose = (args.verbose || dry_run) && !json;
    if args.managed.managed {
        managed::refuse_unless_person()?;
    }
    let home = Home::locate()?;
    let binary = crate::install::hook_binary()?;
    refuse_writable_binary(&home, &binary)?;
    // Why (operator 2026-11-24): the environment snapshot is part of what the
    // install trusts, so the control plane that renders the PATH records it in
    // this same transaction. A person at a terminal may too; every other
    // unattended run keeps the recorded snapshot (`unattended.rs`).
    let person = crate::terminal::person_for("openmoat init");
    let control_plane = installer::authorized();
    let trusted = person || control_plane;
    let snapshot = search_path(&home)?;
    let environment_changed = snapshot.as_ref().is_some_and(|captured| {
        Snapshot::load_in(&home).map_or(true, |stored| captured.differs(&stored))
    });
    let mut out = if json {
        Deferred::quiet()
    } else {
        Deferred::default()
    };
    // Each file written, the backups and the lock: shown with `--verbose`.
    let mut detail = if verbose {
        Deferred::default()
    } else {
        Deferred::quiet()
    };
    let title = if dry_run {
        "what `openmoat init` would change (dry run)"
    } else {
        "protecting the agents on this machine"
    };
    writeln!(
        out,
        "{}\n",
        Style::detect().bold(&format!("OpenMoat {} · {title}", crate::VERSION))
    )?;
    if snapshot.is_none() {
        writeln!(
            out,
            "! environment      {} kept: this shell's PATH finds none of the programs \
             OpenMoat pins; run `openmoat init` from a normal shell to record a new one\n",
            home.environment_path().display()
        )?;
    }
    // Whether a lock existed before this run; `repin` below always leaves one.
    let lock_existed = !dry_run && refuse_repin(&home, &mut out)?;
    // The declared control plane installs the policy it rendered, in the same
    // transaction that re-pins the hooks (ADR-104). A person may do the same
    // at a terminal; every other agent is refused.
    installer::install_declared_policy(&home, args.policy.as_deref(), dry_run, &mut detail)?;
    // No person over an existing lock: what the lock trusts stays (`unattended.rs`).
    // A person may run a binary the lock does not record yet: moving the hooks
    // to it is what `init` is for.
    let unattended = unattended::applies(lock_existed, person);
    // The declared control plane installs an engine release, so moving the
    // hooks to its binary is its job; every other unattended run keeps the
    // recorded binary (ADR-104).
    if unattended && !control_plane {
        let recorded = crate::install::self_paths::recorded_binary(&home)?;
        unattended::refuse_other_binary(&recorded, &binary)?;
    }
    // Asked before anything is written, so declining everything changes nothing
    // but OpenMoat's own state directory.
    let hosts = ask::choose(&home, args, &binary, &mut out)?;

    let mut steps = summary::Steps {
        update: state(
            &home,
            dry_run,
            unattended,
            trusted,
            snapshot.as_ref(),
            &mut detail,
        )?,
        ..summary::Steps::default()
    };
    if !dry_run {
        home.ensure_approval_files()?;
        // Recorded before the files are written: every command from here on,
        // this one included, finds each agent where this shell says it is.
        record(&home, &hosts, unattended)?;
    }
    let mut files = Writers {
        out: &mut out,
        detail: &mut detail,
    };
    let mut host_reports = Vec::with_capacity(hosts.len());
    for host in hosts.iter().copied() {
        host_reports.push(install(
            &home, &binary, host, unattended, dry_run, &mut steps, &mut files,
        )?);
    }
    // The plan says changed when the declared PATH differs from the recorded
    // snapshot, so a deploy installs and records it in the same transaction.
    if environment_changed {
        for report in &mut host_reports {
            report.changed = true;
        }
    }
    if !hooks_only {
        steps.changed |= sandboxes(&home, &binary, &hosts, dry_run, &mut files)?;
    }
    if args.managed.managed {
        managed::write(&home, &binary, &hosts, dry_run, files.out)?;
    }

    let mut lock_entries_count = None;
    if dry_run {
        let detail = &mut *files.detail;
        writeln!(
            detail,
            "would lock             {}",
            home.lock_path().display()
        )?;
        if !hooks_only && args.mcp.mcp_proxy {
            let sandbox = args.mcp.sandbox();
            super::mcp::wrap_servers(&home, &binary, &hosts, &[], sandbox, true, detail)?;
        }
        writeln!(files.out, "dry run: nothing was written")?;
    } else {
        let pins = if hooks_only {
            integrity::HookPins::Selected(&hosts)
        } else {
            integrity::HookPins::Adopt
        };
        let lock = integrity::repin(&home, &binary, pins)?;
        lock_entries_count = Some(lock.entries.len());
        writeln!(
            files.detail,
            "✔ lock             {} ({} files pinned)",
            home.lock_path().display(),
            lock.entries.len()
        )?;
        if !hooks_only {
            let wrap = mcp::Wrap::of(args, unattended);
            mcp::servers(&home, &binary, wrap, &hosts, unattended, &mut files)?;
        }
        let backups = if hosts.is_empty() {
            0
        } else {
            backups(&home, &hosts, files.detail)?
        };
        summary::write(&home, &binary, &hosts, &steps, backups, verbose, files.out)?;
    }
    detail.finish()?;
    out.finish()?;
    if json {
        let binary_sha256 = std::fs::read(&binary)
            .ok()
            .map(|bytes| integrity::sha256_hex(&bytes));
        let protection = if dry_run {
            None
        } else {
            Some(
                crate::protection::report(&home, &binary)?
                    .into_iter()
                    .filter(|item| hosts.iter().any(|h| h.id() == item.host))
                    .collect(),
            )
        };
        let report = InitJsonReport {
            version: crate::VERSION,
            dry_run,
            hooks_only,
            home: home.root().display().to_string(),
            binary: binary.display().to_string(),
            binary_sha256,
            lock_path: home.lock_path().display().to_string(),
            policy_path: home.policy_path().display().to_string(),
            environment_path: home.environment_path().display().to_string(),
            changed: steps.changed || environment_changed,
            lock_entries_count,
            policy_update: steps.update.clone(),
            hosts: host_reports,
            protection,
        };
        crate::render::json(&report)?;
    }
    Ok(Code::Ok)
}

#[derive(Serialize)]
struct InitJsonReport {
    version: &'static str,
    dry_run: bool,
    hooks_only: bool,
    home: String,
    binary: String,
    binary_sha256: Option<String>,
    lock_path: String,
    policy_path: String,
    environment_path: String,
    changed: bool,
    lock_entries_count: Option<usize>,
    policy_update: Option<String>,
    hosts: Vec<InstalledHost>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protection: Option<Vec<crate::protection::Protection>>,
}

#[derive(Serialize)]
struct InstalledHost {
    host: &'static str,
    name: &'static str,
    config_dir: String,
    settings_path: String,
    extra_files: Vec<String>,
    managed_files: Vec<String>,
    events: Vec<&'static str>,
    outcome: &'static str,
    changed: bool,
    backup_path: Option<String>,
    trust_note: Option<&'static str>,
}

/// What `init` prints: what every run shows, and the lines `--verbose` adds.
struct Writers<'a> {
    out: &'a mut Deferred,
    detail: &'a mut Deferred,
}

/// Install `host`'s hook, noting the steps it leaves to the person.
fn install(
    home: &Home,
    binary: &Path,
    host: Host,
    unattended: bool,
    dry_run: bool,
    steps: &mut summary::Steps,
    files: &mut Writers<'_>,
) -> Result<InstalledHost> {
    let prefix = if dry_run { "would" } else { "✔" };
    let config = unattended::config(home, host, unattended)?;
    let replaced = match config.layout {
        HookLayout::Owned(file) | HookLayout::Script(file) => {
            crate::install::owned::persons_file(&config, file)
        }
        HookLayout::Entries(_) | HookLayout::Plugin(_) | HookLayout::Yaml(_) => None,
    };
    let outcome = config.install(home, binary, dry_run)?;
    let verb = match outcome {
        Outcome::Installed => "installed",
        Outcome::Updated => "updated",
        Outcome::Unchanged => "unchanged",
    };
    steps.changed |= outcome != Outcome::Unchanged;
    let events: Vec<&str> = config.hooks.iter().map(|spec| spec.event).collect();
    writeln!(
        files.detail,
        "{prefix} {:<16} {} ({verb}: {} → {}{})",
        host.display_name(),
        config.settings_path.display(),
        events.join(", "),
        binary.display(),
        config.guard(binary).shell_args(host.id())
    )?;
    let backup_path = replaced
        .filter(|_| outcome != Outcome::Unchanged)
        .map(|backup| backup.display().to_string());
    if let Some(backup) = backup_path.as_deref() {
        let move_verb = if dry_run { "would move" } else { "moved" };
        writeln!(
            files.out,
            "! {:<16} {move_verb} your own hook {} to {backup}: {} runs one file there, so yours does \
             not run while OpenMoat is installed; `openmoat uninstall` puts it back",
            host.display_name(),
            config.settings_path.display(),
            host.display_name()
        )?;
    }
    // The agent's own record of trusted hooks: after a change, or while it
    // does not trust the hook yet.
    let trust = crate::install::trust_note::after_install(host, outcome).or_else(|| {
        config
            .trust_warning()
            .and_then(|_| crate::install::trust_note::step(host))
    });
    if let Some(note) = trust {
        writeln!(
            files.detail,
            "{prefix} {:<16} next: {note}",
            host.display_name()
        )?;
        steps.trust.push((host.display_name(), note));
    }
    let extra_files: Vec<String> = config
        .extra_files()
        .into_iter()
        .map(|p| p.display().to_string())
        .collect();
    let mut managed_files = Vec::with_capacity(1 + extra_files.len());
    managed_files.push(config.settings_path.display().to_string());
    managed_files.extend(extra_files.iter().cloned());
    Ok(InstalledHost {
        host: host.id(),
        name: host.display_name(),
        config_dir: config.dir().display().to_string(),
        settings_path: config.settings_path.display().to_string(),
        extra_files,
        managed_files,
        events,
        outcome: verb,
        changed: outcome != Outcome::Unchanged,
        backup_path,
        trust_note: trust,
    })
}

/// Which checks guard `init`'s re-pin of an existing lock.
#[derive(Debug, PartialEq, Eq)]
struct RepinChecks {
    /// Refuse when an agent is among the parent processes.
    agent: bool,
    /// Refuse when pinned files drifted.
    drift: bool,
}

/// The checks for an `init` that writes. A first install has no lock, so
/// nothing to re-pin, and stays open to scripts and the agent setting it up.
/// Over an existing lock an agent is always refused; without a terminal (a
/// script, CI, or a process detached from the agent that started it) drift
/// is refused too, while a person at a terminal re-pins over it as
/// documented, shown what drifted.
fn repin_checks(lock_exists: bool, interactive: bool, control_plane: bool) -> RepinChecks {
    RepinChecks {
        agent: lock_exists && !control_plane,
        drift: lock_exists && !interactive && !control_plane,
    }
}

/// OpenMoat's own state: the directory, the default policy (kept when there is
/// one), the audit log and the search-path snapshot `snapshot` (the recorded
/// one kept when `unattended` or when [`search_path`] found nothing); the
/// update a kept policy can take from this release's default.
fn state(
    home: &Home,
    dry_run: bool,
    unattended: bool,
    trusted: bool,
    snapshot: Option<&Snapshot>,
    out: &mut Deferred,
) -> Result<Option<String>> {
    let prefix = if dry_run { "would" } else { "✔" };
    if !dry_run {
        home.ensure()?;
    }
    writeln!(out, "{prefix} state directory  {}", home.root().display())?;

    let policy_path = home.policy_path();
    let wrote_policy = if dry_run {
        !policy_path.exists()
    } else {
        home.ensure_policy()?
    };
    let mut update = None;
    if wrote_policy {
        writeln!(
            out,
            "{prefix} policy           {} (defaults v1)",
            policy_path.display()
        )?;
    } else {
        writeln!(out, "✔ policy           {} (kept)", policy_path.display())?;
        update = crate::upgrade::available(home);
        if let Some(update) = &update {
            writeln!(
                out,
                "! policy update    {update}: `openmoat policy upgrade` shows them and asks"
            )?;
        }
    }

    // The log and its key (ADR-101), so the first call is keyed.
    let kept = if dry_run {
        None
    } else {
        crate::audit_key::open(home)?
    };
    writeln!(
        out,
        "{prefix} audit log        {}",
        home.audit_path().display()
    )?;
    if let Some(kept) = kept {
        writeln!(
            out,
            "  a new audit log starts with a new audit key; the previous key is kept as {} \
             (it still checks a log you moved aside)",
            kept.display()
        )?;
    }

    if dry_run {
        writeln!(
            out,
            "would environment      {}",
            home.environment_path().display()
        )?;
    } else if unattended && !trusted && home.environment_path().is_file() {
        writeln!(
            out,
            "· environment      {} kept: no person at a terminal to record a new search path",
            home.environment_path().display()
        )?;
    } else if let Some(snapshot) = snapshot {
        snapshot.save(&home.environment_path())?;
        writeln!(
            out,
            "✔ environment      {} ({} dirs, {} programs pinned)",
            home.environment_path().display(),
            snapshot.path.len(),
            snapshot.programs.len()
        )?;
    } else {
        writeln!(
            out,
            "· environment      {} kept",
            home.environment_path().display()
        )?;
    }
    Ok(update)
}

/// This shell's search path, as `init` records it; `None` when it finds none
/// of [`PINNED_PROGRAMS`](crate::environment::PINNED_PROGRAMS) (an empty or
/// broken `PATH`, a service's bare environment) and a snapshot is recorded
/// already, which is then kept. Without one it is refused: a snapshot that
/// pins nothing would check no program the guard resolves, and `init` would
/// say it succeeded.
fn search_path(home: &Home) -> Result<Option<Snapshot>> {
    let snapshot = Snapshot::capture();
    if !snapshot.programs.is_empty() {
        return Ok(Some(snapshot));
    }
    if home.environment_path().is_file() {
        return Ok(None);
    }
    bail!(
        "this shell's PATH finds none of the programs OpenMoat pins (sh, git, curl, …), so \
         there is no search path to record and nothing was changed; run `openmoat init` from a \
         normal shell"
    )
}

/// The backups `init` made of `hosts`' files, and how to undo; how many.
fn backups(home: &Home, hosts: &[Host], out: &mut Deferred) -> Result<usize> {
    let recorded = Recorded::load(home)?;
    let mut backups = Vec::new();
    for host in hosts {
        for file in host_files(&HostConfig::for_host(home, *host)?) {
            let made = crate::install::backups(&file);
            backups.extend(made.into_iter().filter(|b| recorded.owns(b)));
        }
    }
    let backups: Vec<String> = backups.iter().map(|p| p.display().to_string()).collect();
    if backups.is_empty() {
        writeln!(
            out,
            "· backups          none: the agents had no files to back up"
        )?;
    } else {
        writeln!(out, "✔ backups          {}", backups.join(", "))?;
    }
    Ok(backups.len())
}

/// Every file `init` may change for `config`'s host: its hook file, its
/// sandbox file beside it when that is another file (Codex's `config.toml`,
/// Cursor's `sandbox.json`), and its other hook files (OpenClaw's plugin).
fn host_files(config: &HostConfig) -> Vec<PathBuf> {
    let mut files = vec![config.settings_path.clone()];
    let spec = config.host.spec();
    if let (Some(sandbox), Some(install)) = (&spec.sandbox, &spec.install)
        && sandbox.file != install.config_file
    {
        files.push(config.settings_path.with_file_name(sandbox.file));
    }
    files.extend(config.extra_files());
    files
}

/// Record where each of `hosts` keeps its configuration, so later commands
/// find it without this shell's environment (`hosts.json`, pinned by the lock);
/// `unattended`, a recorded host keeps its record.
fn record(home: &Home, hosts: &[Host], unattended: bool) -> Result<()> {
    let mut recorded = Recorded::load(home)?;
    for host in hosts {
        let config = HostConfig::for_init(home, *host)?;
        unattended::record(&mut recorded, &config, unattended);
    }
    recorded.save(home)
}

/// The sandbox plan for the policy in place, or the default one `init` would
/// install.
fn sandbox_plan(home: &Home, binary: &std::path::Path) -> Result<Plan> {
    let policy = if home.policy_path().exists() {
        home.load_policy()?
    } else {
        Policy::parse(DEFAULT_POLICY)?
    };
    Plan::for_binary(home, &policy, binary)
}

/// Standard tier (ADR-018): each selected host's own sandbox, configured from
/// the policy. A policy that does not lint is reported, not fatal, so `init`
/// can still repair hooks; `moat sandbox sync` writes the sandboxes later.
/// Whether a sandbox changed.
fn sandboxes(
    home: &Home,
    binary: &std::path::Path,
    hosts: &[Host],
    dry_run: bool,
    files: &mut Writers<'_>,
) -> Result<bool> {
    let prefix = if dry_run { "would" } else { "✔" };
    let selected: Vec<Host> = sandbox::install::hosts()
        .filter(|h| hosts.contains(h))
        .collect();
    if selected.is_empty() {
        return Ok(false);
    }
    let plan = match sandbox_plan(home, binary) {
        Ok(plan) => plan,
        Err(e) => {
            writeln!(files.out, "✗ sandbox          not written: {e:#}")?;
            return Ok(false);
        }
    };
    let out = &mut *files.detail;
    let mut any = false;
    for host in selected {
        let changed = sandbox::install::write(home, host, &plan, dry_run)?;
        any |= changed;
        if let Some(note) = sandbox::install::unavailable(host) {
            if changed {
                writeln!(
                    out,
                    "{prefix} {:<16} {}",
                    host.display_name(),
                    sandbox::install::old_sandbox_removed(host)
                )?;
            }
            writeln!(out, "· {:<16} {note}", host.display_name())?;
            continue;
        }
        let verb = if changed { "updated" } else { "unchanged" };
        let report = sandbox::install::report(host, &plan);
        writeln!(
            out,
            "{prefix} {:<16} {} (sandbox {verb}; {} stricter, {} wider than the policy: `openmoat sandbox show`)",
            host.display_name(),
            sandbox::install::settings_path(home, host)?.display(),
            report.losses.len(),
            report.allowances.len()
        )?;
    }
    Ok(any)
}
