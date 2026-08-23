use std::process::Command;

#[test]
fn help_documents_core_operator_controls() {
    let output = Command::new(env!("CARGO_BIN_EXE_gitrecon"))
        .arg("--help")
        .output()
        .expect("run gitrecon --help");
    assert!(output.status.success(), "--help should exit successfully");
    let help = String::from_utf8(output.stdout).expect("help output is UTF-8");
    for option in [
        "--exhaustive",
        "--no-scan-binaries",
        "--checkpoint-dir",
        "--checkpoint-interval",
        "--partial-exposure",
        "--parallel-targets",
        "--scan-scope",
        "--pipe",
        "--format",
        "--cache-stats",
        "--cache-clear",
    ] {
        assert!(help.contains(option), "help output lacks {option}");
    }
}

#[test]
fn cache_stats_no_cache_is_standalone_and_machine_readable() {
    let output = Command::new(env!("CARGO_BIN_EXE_gitrecon"))
        .args(["--cache-stats", "--no-cache", "--pipe", "--no-color"])
        .output()
        .expect("run cache stats");

    assert!(
        output.status.success(),
        "cache stats should exit successfully"
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cache stats output is JSON");
    assert_eq!(json["type"], "cache_stats");
    assert_eq!(json["enabled"], false);
    assert_eq!(json["reason"], "disabled_by_flag");
}

#[test]
fn cache_clear_no_cache_is_standalone_and_machine_readable() {
    let output = Command::new(env!("CARGO_BIN_EXE_gitrecon"))
        .args(["--cache-clear", "--no-cache", "--pipe", "--no-color"])
        .output()
        .expect("run cache clear");

    assert!(
        output.status.success(),
        "cache clear should exit successfully"
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cache clear output is JSON");
    assert_eq!(json["type"], "cache_clear");
    assert_eq!(json["enabled"], false);
    assert_eq!(json["cleared"], false);
    assert_eq!(json["reason"], "disabled_by_flag");
}
