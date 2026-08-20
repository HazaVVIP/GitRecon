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
        "--parallel-targets",
        "--pipe",
        "--format",
    ] {
        assert!(help.contains(option), "help output lacks {option}");
    }
}
