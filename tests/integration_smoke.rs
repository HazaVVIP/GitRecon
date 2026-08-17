use std::process::Command;

#[test]
fn cli_help_succeeds() {
    let output = Command::new(env!("CARGO_BIN_EXE_gitrecon"))
        .arg("--help")
        .output()
        .expect("failed to execute gitrecon --help");

    assert!(output.status.success(), "expected --help to succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("GitRecon"));
}

#[test]
fn cli_rejects_empty_invocation() {
    let output = Command::new(env!("CARGO_BIN_EXE_gitrecon"))
        .output()
        .expect("failed to execute gitrecon");

    assert!(!output.status.success(), "expected empty invocation to fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Either <URL>") || stderr.contains("required"));
}
