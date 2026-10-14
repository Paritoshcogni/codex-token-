#![cfg(unix)]

mod common;

#[test]
fn missing_filtered_binary_reports_command_not_found_and_exit_127() {
    let empty_path = tempfile::tempdir().expect("create empty PATH directory");
    let output = common::rtk_command()
        .args(["phpstan", "--version"])
        .env("PATH", empty_path.path())
        .output()
        .expect("run rtk phpstan");

    assert_eq!(output.status.code(), Some(127));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim(),
        "rtk: phpstan: command not found"
    );
}

#[test]
fn missing_proxy_binary_reports_command_not_found_and_exit_127() {
    let empty_path = tempfile::tempdir().expect("create empty PATH directory");
    let output = common::rtk_command()
        .args(["proxy", "rtk-missing-command-3273"])
        .env("PATH", empty_path.path())
        .output()
        .expect("run rtk proxy");

    assert_eq!(output.status.code(), Some(127));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim(),
        "rtk: rtk-missing-command-3273: command not found"
    );
}
