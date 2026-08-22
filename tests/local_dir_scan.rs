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
fn dry_run_directory_validates_without_scanning_or_writing_report() {
    let root = tempfile::tempdir().expect("create fixture directory");
    let output = tempfile::tempdir().expect("create output directory");
    fs::write(root.path().join("config.txt"), b"synthetic content\n").expect("write fixture");

    let result = Command::new(env!("CARGO_BIN_EXE_gitrecon"))
        .args([
            "--dir",
            root.path().to_str().expect("fixture path is UTF-8"),
            "--output",
            output.path().to_str().expect("output path is UTF-8"),
            "--format",
            "json",
            "--dry-run",
            "--no-color",
        ])
        .output()
        .expect("run gitrecon dry-run");

    assert!(
        result.status.success(),
        "gitrecon exited with {}",
        result.status
    );
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(stdout.contains("no network or content scan performed"));
    assert!(fs::read_dir(output.path())
        .expect("read output directory")
        .next()
        .is_none());
}

#[test]
fn dry_run_targets_emits_json_without_dispatching_scans() {
    let root = tempfile::tempdir().expect("create fixture directory");
    let output = tempfile::tempdir().expect("create output directory");
    let targets = root.path().join("targets.ndjson");
    fs::write(
        &targets,
        format!(
            "https://example.test\n{{\"dir\":\"{}\"}}\n",
            root.path().display()
        ),
    )
    .expect("write targets fixture");

    let result = Command::new(env!("CARGO_BIN_EXE_gitrecon"))
        .args([
            "--targets",
            targets.to_str().expect("targets path is UTF-8"),
            "--output",
            output.path().to_str().expect("output path is UTF-8"),
            "--dry-run",
            "--pipe",
            "--no-color",
        ])
        .output()
        .expect("run gitrecon dry-run");

    assert!(
        result.status.success(),
        "gitrecon exited with {}",
        result.status
    );
    let json: serde_json::Value =
        serde_json::from_slice(&result.stdout).expect("parse dry-run JSON");
    assert_eq!(json["type"], "dry_run");
    assert_eq!(json["valid"], true);
    assert_eq!(json["targets"], 2);
    assert_eq!(json["network"], "skipped");
    assert_eq!(json["content_scan"], "skipped");
    assert!(fs::read_dir(output.path())
        .expect("read output directory")
        .next()
        .is_none());
}

#[test]
fn dry_run_url_skips_network_and_emits_pipe_json() {
    let result = Command::new(env!("CARGO_BIN_EXE_gitrecon"))
        .args(["https://example.test", "--dry-run", "--pipe", "--no-color"])
        .output()
        .expect("run URL dry-run");

    assert!(
        result.status.success(),
        "gitrecon exited with {}",
        result.status
    );
    let json: serde_json::Value =
        serde_json::from_slice(&result.stdout).expect("parse dry-run JSON");
    assert_eq!(json["type"], "dry_run");
    assert_eq!(json["targets"], 1);
    assert_eq!(json["network"], "skipped");
}

#[test]
fn dry_run_invalid_token_fails_before_authentication() {
    let result = Command::new(env!("CARGO_BIN_EXE_gitrecon"))
        .args(["--token", "invalid", "--dry-run", "--quiet", "--no-color"])
        .output()
        .expect("run token dry-run");

    assert!(
        !result.status.success(),
        "invalid token should fail validation"
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("Dry-run validation failed"));
    assert!(stderr.contains("Invalid GitHub token"));
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
fn local_directory_scan_applies_custom_pattern_to_binary_content() {
    let root = tempfile::tempdir().expect("create fixture directory");
    let output = tempfile::tempdir().expect("create output directory");
    let pattern_file = std::env::current_dir()
        .expect("read test working directory")
        .join(format!(
            ".gitrecon-custom-pattern-{}.json",
            std::process::id()
        ));
    fs::write(
        &pattern_file,
        r#"{"patterns":[{"id":"custom_binary","severity":"CRITICAL","description":"Custom binary marker","regex":"CUSTOM_[A-Z0-9]{4}"}]}"#,
    )
    .expect("write pattern fixture");
    let binary = root.path().join("fixture.bin");
    let mut data = vec![0u8; 32];
    data.extend_from_slice(b"CUSTOM_AB12");
    fs::write(binary, data).expect("write binary fixture");

    let status = Command::new(env!("CARGO_BIN_EXE_gitrecon"))
        .args([
            "--dir",
            root.path().to_str().expect("fixture path is UTF-8"),
            "--patterns",
            pattern_file.to_str().expect("pattern path is UTF-8"),
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
    assert!(body.contains("custom_binary"));
    assert!(body.contains("Custom binary marker"));
    assert!(body.contains("CUSTOM_AB12"));
    assert!(body.contains("CRITICAL"));
    fs::remove_file(pattern_file).expect("remove pattern fixture");
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
