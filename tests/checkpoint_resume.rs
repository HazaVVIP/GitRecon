use std::process::Command;

#[test]
fn resume_uses_custom_checkpoint_directory() {
    let checkpoint_dir = tempfile::tempdir().expect("create checkpoint directory fixture");
    let output_dir = tempfile::tempdir().expect("create output directory fixture");
    let status = Command::new(env!("CARGO_BIN_EXE_gitrecon"))
        .args([
            "--resume",
            "--checkpoint-dir",
            checkpoint_dir
                .path()
                .to_str()
                .expect("checkpoint path is UTF-8"),
            "--output",
            output_dir.path().to_str().expect("output path is UTF-8"),
            "--no-color",
            "--quiet",
        ])
        .status()
        .expect("run gitrecon");

    assert!(
        status.success(),
        "resume without checkpoints should exit cleanly"
    );
    assert!(
        checkpoint_dir.path().is_dir(),
        "custom checkpoint directory should be created and inspected"
    );
}
