# ADR-008: Executable pinning through a caller-supplied `ProgramResolver`

Status: accepted · Date: 2026-10-03 (#13, #14)

## Context

A shell rule names a program by its first word. `git` may be `/usr/bin/git`, a copy in
`node_modules/.bin` planted by a dependency, or a file in a directory an earlier command
prepended to `PATH` (`DESIGN.md` G3, T5). Checking this needs the filesystem, and
`moat-core` must stay pure: no I/O, builds for `wasm32`, dependency allowlist enforced by
an architecture test.

## Decision

- `moat-core` defines `trait ProgramResolver { fn resolve(&self, name) -> Option<path>;
  fn pinned(&self, name) -> Option<path> }` and `programs::check`, which compares the
  path a command's program resolves to with its pins: the policy's `executables:` table
  plus the installation pin. A mismatch, or a pinned program that cannot be resolved, is
  `deny` with rule `executables`. Unpinned programs are not checked. An argv0 that
  contains a path separator is compared literally.
- `CompiledPolicy::decide_with(action, &resolver)` takes the resolver;
  `CompiledPolicy::decide` uses `NoResolver` (unit tests, `moat policy check`).
- `moat init` captures `PATH` and the absolute location of a fixed list of
  security-relevant programs (`sh`, `git`, `curl`, `node`, `npm`, `python3`, `cargo`,
  `sudo`, …) into `~/.moat/environment.json`, pinned by the lock. `moat guard` loads the
  snapshot and resolves through *that* search path, never the hook's inherited
  environment.

## Consequences

- Planted binaries and `PATH` poisoning are caught at decision time for pinned programs,
  including absolute-path invocations of a copy elsewhere.
- Installing a tool in a new location requires `moat init` or `moat doctor --accept`.
- `moat policy check` has no snapshot: policy `executables:` pins deny bare program names
  as "not found" there; testing pins needs `guard` or a real hook.
- Known gaps (audit 2026-10-05): an empty `PATH` at init pins nothing and still reports
  success; on Windows only `.exe`, `.cmd` and `.bat` are tried, `PATHEXT` is ignored.
- Core purity holds; the only filesystem code is `crates/moat-cli/src/environment.rs`.

## Amendment 2026-11-24 — a pin names a file, not a spelling

- `ProgramResolver` gains `same_file(a, b)`, defaulting to string equality so callers
  without a filesystem (tests, `wasm32`) stay sound. The CLI implements it with the
  file's device and inode, or the canonical paths where the platform has neither.
  `programs::check` accepts any path that names the pinned file, so a distribution's
  hardlink (`/usr/bin/git` and `/usr/sbin/git` are one inode) and a project's virtualenv
  symlink to the recorded interpreter pass, while a planted copy is still denied.
- A path-invoked program is resolved against the call's own working directory through
  `paths::normalise` before the comparison, following a leading `cd` in the same command
  line, so `.venv/bin/python` is compared as the absolute file it runs.
- A program named by an explicit path inside the project root the caller resolves — the CLI
  answers through `ProjectResolver`; the core never touches the filesystem — is the
  project's choice, like the package runner ADR-102 trusts under `node_modules/.bin`, and
  is not compared with a machine pin; a bare name, or a path outside the root, still is.
  This is what lets a repository's `.venv/bin/python` run without making every copy of
  `python3` acceptable.
- The anchored `init` records the PATH the control plane renders in the same transaction
  that installs the policy and pins the lock; its plan reports the snapshot as changed when
  it differs, so convergence refreshes it. `init` without a terminal and without the
  anchor keeps the recorded snapshot.

