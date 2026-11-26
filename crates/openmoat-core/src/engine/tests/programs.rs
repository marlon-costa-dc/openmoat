//! Program-resolution decisions for the engine.
//!
//! Why: split from `tests.rs` so the file stays inside the crate's size budget.
//! The two tests are unchanged; only their owning module moved.

use super::*;

#[test]
fn a_cd_moves_where_a_relative_program_resolves() {
    let ctx = ctx();
    assert_eq!(
        cd_target(&["cd".into(), "repo".into()], &ctx, &ctx.cwd),
        Some("/p/repo".into())
    );
    assert_eq!(
        cd_target(&["cd".into(), "/tmp/x".into()], &ctx, &ctx.cwd),
        Some("/tmp/x".into())
    );
    assert_eq!(cd_target(&["cd".into(), "-".into()], &ctx, &ctx.cwd), None);
    assert_eq!(cd_target(&["ls".into()], &ctx, &ctx.cwd), None);
}

/// A program the project vendors is the project's choice: a pin is about the
/// machine's search path, not about the project's own files.
#[test]
fn a_vendored_program_inside_the_project_is_not_a_pin_mismatch() {
    use crate::programs::{MapResolver, ProjectResolver};

    struct Projects;
    impl ProjectResolver for Projects {
        fn root_of(&self, dir: &str) -> Option<String> {
            (dir == "/p").then(|| "/p".to_owned())
        }
    }

    let p = policy("version: 1\ndefaults: allow\nexecutables:\n  python3: ['/usr/bin/python3']\n");
    let compiled = CompiledPolicy::compile(&p, &ctx()).unwrap();
    let resolver = MapResolver::default();
    let inside = compiled.decide_with_projects(
        &shell("cd /p && .venv/bin/python3 -c 'print(1)'"),
        &resolver,
        &NoResolver,
        &Projects,
    );
    assert_eq!(inside.verdict, Verdict::Allow);
    let outside = compiled.decide_with_projects(
        &shell("/tmp/x/python3 -c 'print(1)'"),
        &resolver,
        &NoResolver,
        &Projects,
    );
    assert_eq!(outside.verdict, Verdict::Deny);
}
