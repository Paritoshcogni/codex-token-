//! git writes its usage page to stdout and exits 129. The git handlers used to print only
//! stderr on a non-zero exit, so the page was lost. Each case compares rtk's stdout to
//! git's own for the same arguments.

use std::path::Path;
use std::process::Command;

mod common;

fn git_out(repo: &Path, sub: &str, args: &[&str]) -> (Vec<u8>, Option<i32>) {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(repo).arg(sub).args(args);
    common::isolate_git(&mut cmd);
    let out = cmd.output().expect("run git");
    (out.stdout, out.status.code())
}

fn rtk_out(repo: &Path, sub: &str, args: &[&str]) -> (Vec<u8>, Option<i32>) {
    let mut cmd = common::rtk_command();
    cmd.arg("git").arg(sub).args(args).current_dir(repo);
    common::isolate_git(&mut cmd);
    let out = cmd.output().expect("run rtk");
    (out.stdout, out.status.code())
}

fn assert_usage_kept(sub: &str, args: &[&str]) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut init = Command::new("git");
    init.arg("-C").arg(dir.path()).args(["init", "-q"]);
    common::isolate_git(&mut init);
    assert!(init.status().expect("git init").success());

    let (want, want_code) = git_out(dir.path(), sub, args);
    assert_eq!(want_code, Some(129), "git {sub} {args:?} should exit 129");
    assert!(
        !want.is_empty(),
        "git {sub} {args:?} should print usage on stdout"
    );
    let (got, got_code) = rtk_out(dir.path(), sub, args);
    assert_eq!(got_code, Some(129));
    assert_eq!(
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(&want),
        "rtk git {sub} {args:?} must print git's usage page"
    );
}

#[test]
fn log_m_h_prints_usage() {
    assert_usage_kept("log", &["-m", "-h"]);
}

#[test]
fn log_m_help_prints_usage() {
    assert_usage_kept("log", &["-m", "--help"]);
}

#[test]
fn show_m_help_prints_usage() {
    assert_usage_kept("show", &["-m", "--help"]);
}

#[test]
fn fetch_m_help_prints_usage() {
    assert_usage_kept("fetch", &["-m", "--help"]);
}
