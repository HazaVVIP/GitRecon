use std::fs;
use std::process::Command;

#[test]
fn local_directory_scan_detects_secret_and_writes_json_report() {
    let root = tempfile::tempdir().expect("create fixture directory");
    let output = tempfile::tempdir().expect("create output directory");
    let source = root.path().join("config.txt");
    fs::write(
        &source,
        b"AWS_ACCESS_KEY_ID=AKIAZ9XYZMNOP1234567\nordinary text\n",
    )
    .expect("write fixture");

    let status = Command::new(env!("CARGO_BIN_EXE_gitrecon"))
        .args([
            "--dir",
            root.path().to_str().expect("fixture path is UTF-8"),
            "--output",
            output.path().to_str().expect("output path is UTF-8"),
            "--format",
            "json",
            "--no-color",
            "--quiet",
        ])
        .status()
        .expect("run gitrecon");
    assert!(status.success(), "gitrecon exited with {status}");

    let report = fs::read_dir(output.path())
        .expect("read output directory")
        .map(|entry| entry.expect("read report entry").path())
        .find(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .expect("JSON report was not generated");
    let body = fs::read_to_string(report).expect("read JSON report");
    let json: serde_json::Value = serde_json::from_str(&body).expect("parse JSON report");
    assert!(
        json["result"]["findings"].as_array().is_some(),
        "report lacks result.findings array"
    );
    assert!(
        body.contains("aws_key_id"),
        "report does not contain the detected AWS key rule"
    );
    assert!(
        body.contains("AKIAZ9XYZMNOP1234567"),
        "report does not contain the matched finding"
    );
}

#[test]
fn local_directory_scan_binary_placeholder_policy_is_exhaustive() {
    let root = tempfile::tempdir().expect("create fixture directory");
    let normal_output = tempfile::tempdir().expect("create normal output directory");
    let exhaustive_output = tempfile::tempdir().expect("create exhaustive output directory");
    let binary = root.path().join("fixture.bin");
    let mut data = vec![0u8; 32];
    let aws_placeholder = ["AKIA", "IOSFODNN7EXAMPLE"].concat();
    data.extend_from_slice(aws_placeholder.as_bytes());
    fs::write(&binary, data).expect("write binary fixture");

    for (output, exhaustive) in [
        (normal_output.path(), false),
        (exhaustive_output.path(), true),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitrecon"));
        command.args([
            "--dir",
            root.path().to_str().expect("fixture path is UTF-8"),
            "--output",
            output.to_str().expect("output path is UTF-8"),
            "--format",
            "json",
            "--no-color",
            "--quiet",
        ]);
        if exhaustive {
            command.arg("--exhaustive");
        }
        let status = command.status().expect("run gitrecon");
        assert!(status.success(), "gitrecon exited with {status}");
    }

    let read_report = |output: &std::path::Path| {
        let report = fs::read_dir(output)
            .expect("read output directory")
            .map(|entry| entry.expect("read report entry").path())
            .find(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
            .expect("JSON report was not generated");
        fs::read_to_string(report).expect("read JSON report")
    };
    assert!(
        !read_report(normal_output.path()).contains(&aws_placeholder),
        "normal binary scans should filter canonical placeholder candidates"
    );
    assert!(
        read_report(exhaustive_output.path()).contains(&aws_placeholder),
        "exhaustive binary scans should retain canonical placeholder candidates"
    );
}

#[test]
fn local_directory_scan_rejects_missing_directory() {
    let output = tempfile::tempdir().expect("create output directory");
    let missing = output.path().join("does-not-exist");
    let status = Command::new(env!("CARGO_BIN_EXE_gitrecon"))
        .args([
            "--dir",
            missing.to_str().expect("missing path is UTF-8"),
            "--output",
            output.path().to_str().expect("output path is UTF-8"),
            "--quiet",
        ])
        .status()
        .expect("run gitrecon");
    assert!(
        !status.success(),
        "missing directory should fail validation"
    );
}
