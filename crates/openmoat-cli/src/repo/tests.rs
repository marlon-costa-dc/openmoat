use super::*;

fn project() -> (tempfile::TempDir, Home, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("state"));
    let root = dir.path().join("project");
    fs::create_dir_all(&root).unwrap();
    (dir, home, root)
}

#[test]
fn no_policy_directory_or_a_file_in_its_place_is_no_repo_policy() {
    let (_dir, home, root) = project();
    assert!(find(&home, &root).unwrap().is_none());
    // The empty placeholder `moat run --isolate` leaves at `.moat`.
    fs::write(root.join(home::DIR_NAME), "").unwrap();
    assert!(find(&home, &root).unwrap().is_none());
}

/// With `require_signed_repo_policy: true` a `moat trust` record is not enough:
/// an unsigned file, or one whose signature no trusted key made, only tightens.
#[test]
fn requiring_signatures_ignores_a_trust_record_without_one() {
    let (_dir, home, root) = project();
    let path = root.join(home::DIR_NAME).join("policy.yaml");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        "version: 1\nallow:\n  - id: bundle\n    shell: ['make bundle']\n",
    )
    .unwrap();
    let found = find(&home, &root).unwrap().unwrap();
    fs::create_dir_all(home.root()).unwrap();
    let mut records = Trust::default();
    records
        .repos
        .insert(found.root.clone(), found.digest.clone());
    records.save(&home.trust_path()).unwrap();
    Lock::pin(&home.trust_path(), &[home.trust_path()])
        .unwrap()
        .save(&home.lock_path())
        .unwrap();

    let default = Policy::parse("version: 1\n").unwrap();
    assert!(
        is_trusted(&home, &default, &found).unwrap(),
        "openmoat trust"
    );
    let signed_only = Policy::parse("version: 1\nrequire_signed_repo_policy: true\n").unwrap();
    assert!(
        !is_trusted(&home, &signed_only, &found).unwrap(),
        "unsigned"
    );
    // No key is trusted, so no signature can verify.
    fs::write(signature_path(&found), "not a signature").unwrap();
    assert!(
        !is_trusted(&home, &signed_only, &found).unwrap(),
        "no trusted key"
    );
    assert!(
        is_trusted(&home, &default, &found).unwrap(),
        "unchanged by default"
    );
}

#[test]
fn a_policy_that_exists_but_is_no_file_or_malformed_is_an_error() {
    let (_dir, home, root) = project();
    let path = root.join(home::DIR_NAME).join("policy.yaml");
    fs::create_dir_all(&path).unwrap();
    let error = format!("{:#}", find(&home, &root).err().unwrap());
    assert!(error.contains("not a regular file"), "{error}");
    fs::remove_dir(&path).unwrap();
    fs::write(&path, "version: 1\ndeny: [\n").unwrap();
    let error = format!("{:#}", find(&home, &root).err().unwrap());
    assert!(error.contains("invalid repository policy"), "{error}");
}

/// A linked worktree is the same repository: with no policy of its own it
/// reads the main checkout's, so the repository's rules apply where the
/// agents work.
#[test]
fn a_linked_worktree_reads_the_main_worktrees_policy() {
    let (dir, home, main) = project();
    let worktree = dir.path().join("worktree");
    fs::create_dir_all(main.join(home::DIR_NAME)).unwrap();
    fs::write(
        main.join(home::DIR_NAME).join("policy.yaml"),
        "version: 1\ndeny:\n  - id: test-block\n    reason: test\n    shell: ['false']\n",
    )
    .unwrap();
    fs::create_dir_all(main.join(".git/worktrees/wt")).unwrap();
    fs::write(main.join(".git/worktrees/wt/commondir"), "../..").unwrap();
    fs::create_dir_all(&worktree).unwrap();
    fs::write(
        worktree.join(".git"),
        format!("gitdir: {}\n", main.join(".git/worktrees/wt").display()),
    )
    .unwrap();

    let found = find(&home, &worktree)
        .unwrap()
        .expect("main worktree policy");
    assert_eq!(found.path, main.join(home::DIR_NAME).join("policy.yaml"));
    assert_eq!(found.root, root_key(&main).unwrap());
}
