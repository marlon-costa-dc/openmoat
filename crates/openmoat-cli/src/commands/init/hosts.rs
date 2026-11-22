//! Select the agents `init` will set up.

use std::io::Write as _;
use std::path::Path;

use anyhow::Result;
use openmoat_hosts::Host;

use super::{ask, sandbox_plan};
use crate::cli::InitArgs;
use crate::home::Home;
use crate::install::{HostConfig, dir_variable, env_config_dir};
use crate::render::Deferred;

/// The hosts to set up: `--hosts` as given; else every host found, each confirmed
/// at the terminal (all of them with `--yes` or `--dry-run`, none without a
/// terminal, so a script never changes an agent's files unasked).
pub(super) fn choose(
    home: &Home,
    args: &InitArgs,
    binary: &Path,
    out: &mut Deferred,
) -> Result<Vec<Host>> {
    if let Some(explicit) = &args.hosts {
        return supported(explicit.iter().copied(), out);
    }
    let mut found = Vec::new();
    for config in Host::ALL
        .into_iter()
        .filter_map(|h| HostConfig::for_init(home, h).ok())
    {
        if config.host_present() {
            found.push(config);
        } else if env_config_dir(config.host)?.is_some()
            && crate::install::location::custom(config.host)
                .is_none_or(openmoat_hosts::Locate::variables_are_the_hosts)
        {
            // The agent creates its directory on first start; say so instead of
            // leaving it out silently. The directory is not created here.
            let name = config.host.display_name();
            writeln!(
                out,
                "· {name}: {} is {}, which does not exist yet; start {name} once to create \
                 it, then run openmoat init again",
                dir_variable(config.host)?.0,
                config.dir().display()
            )?;
        }
    }
    let takes_hook = supported(found.iter().map(|c| c.host), out)?;
    found.retain(|c| takes_hook.contains(&c.host));
    let names: Vec<&str> = found.iter().map(|c| c.host.display_name()).collect();
    if found.is_empty() {
        writeln!(out, "· No agents found; pass --hosts to set one up")?;
        return Ok(Vec::new());
    }
    if args.yes || args.dry_run {
        return Ok(found.iter().map(|c| c.host).collect());
    }
    if !crate::terminal::interactive() {
        writeln!(
            out,
            "! OpenMoat found {}; none changed without a terminal: run `openmoat init` \
             in a terminal to choose, or `openmoat init --yes` to set up all of them",
            names.join(", ")
        )?;
        return Ok(Vec::new());
    }
    // The sandbox settings the policy `init` keeps or installs gives each agent.
    let plan = sandbox_plan(home, binary).ok();
    let asking = ask::Asking {
        plan: plan.as_ref(),
        verbose: args.verbose,
        every_agent: args.mcp.mcp_proxy,
    };
    let chosen = ask::ask(home, &found, binary, &asking, out)?;
    if chosen.is_empty() {
        writeln!(out, "· No agent accepted; no agent's files were changed")?;
    }
    Ok(chosen)
}

/// `hosts` but those whose version on the search path does not take OpenMoat's
/// hook (OpenCode before 1.3.4), each named with why it is not set up: a hook it does not
/// load would be pinned and reported as protecting nothing.
fn supported(hosts: impl Iterator<Item = Host>, out: &mut Deferred) -> Result<Vec<Host>> {
    let mut kept = Vec::new();
    for host in hosts {
        match crate::install::host_version::unsupported(host) {
            Some(why) => writeln!(out, "· {:<16} not set up: {why}", host.display_name())?,
            None => kept.push(host),
        }
    }
    Ok(kept)
}
