use std::fs;
use std::process::Command;

#[test]
fn mixed_targets_write_aggregate_outcomes() {
    let root = tempfile::tempdir().expect("create fixture root");
    let output = root.path().join("output");
    let scan_dir = root.path().join("scan");
    fs::create_dir_all(&scan_dir).expect("create scan directory");
    fs::write(
        scan_dir.join("config.env"),
        "AWS_ACCESS_KEY_ID=AKIAZ9XYZMNOP1234567\n",
    )
    .expect("write scan fixture");

    let targets = root.path().join("targets.ndjson");
    let target_file = format!(
        "{url}\n{{\"token\":\"invalid-token\"}}\n{{\"dir\":{dir:?}}}\n",
        url = "http://127.0.0.1:9",
        dir = scan_dir.to_string_lossy(),
    );
    fs::write(&targets, target_file).expect("write targets fixture");

    let status = Command::new(env!("CARGO_BIN_EXE_gitrecon"))
        .args([
            "--targets",
            targets.to_str().expect("targets path is UTF-8"),
            "--output",
            output.to_str().expect("output path is UTF-8"),
            "--quiet",
            "--timeout",
            "1",
            "--retries",
            "0",
        ])
        .status()
        .expect("run gitrecon");
    assert!(
        status.success(),
        "one failed target must not abort aggregate scan"
    );

    let aggregate = output.join("aggregate_report.json");
    let body = fs::read_to_string(&aggregate).expect("read aggregate report");
    let report: serde_json::Value = serde_json::from_str(&body).expect("parse aggregate report");
    assert_eq!(report["total_targets"], 3);
    assert_eq!(report["scanned_targets"], 3);

    let results = report["results"].as_array().expect("results array");
    assert_eq!(results.len(), 3);
    assert!(results
        .iter()
        .any(|r| r["target_type"] == "DIR" && r["status"] == "success"));
    assert!(results
        .iter()
        .any(|r| r["target_type"] == "TOKEN" && r["status"] == "failed"));
    assert!(results.iter().any(|r| r["target_type"] == "URL"));
}

#[test]
fn mixed_targets_missing_file_fails_cleanly() {
    let root = tempfile::tempdir().expect("create fixture root");
    let missing = root.path().join("missing.ndjson");
    let output = root.path().join("output");
    let status = Command::new(env!("CARGO_BIN_EXE_gitrecon"))
        .args([
            "--targets",
            missing.to_str().expect("targets path is UTF-8"),
            "--output",
            output.to_str().expect("output path is UTF-8"),
            "--quiet",
        ])
        .status()
        .expect("run gitrecon");
    assert!(
        !status.success(),
        "missing targets file must fail validation"
    );
}

#[test]
fn mixed_targets_parallel_preserves_input_order() {
    let root = tempfile::tempdir().expect("create fixture root");
    let output = root.path().join("output");
    let scan_dir = root.path().join("scan");
    fs::create_dir_all(&scan_dir).expect("create scan directory");
    fs::write(
        scan_dir.join("config.env"),
        "AWS_ACCESS_KEY_ID=AKIAZ9XYZMNOP1234567\n",
    )
    .expect("write scan fixture");
    let targets = root.path().join("targets.ndjson");
    let target_file = format!(
        "{url}\n{{\"token\":\"invalid-token\"}}\n{{\"dir\":{dir:?}}}\n",
        url = "http://127.0.0.1:9",
        dir = scan_dir.to_string_lossy(),
    );
    fs::write(&targets, target_file).expect("write targets fixture");

    let status = Command::new(env!("CARGO_BIN_EXE_gitrecon"))
        .args([
            "--targets",
            targets.to_str().expect("targets path is UTF-8"),
            "--output",
            output.to_str().expect("output path is UTF-8"),
            "--parallel-targets",
            "3",
            "--quiet",
            "--timeout",
            "1",
            "--retries",
            "0",
        ])
        .status()
        .expect("run gitrecon");
    assert!(
        status.success(),
        "parallel target failures must be isolated"
    );

    let body =
        fs::read_to_string(output.join("aggregate_report.json")).expect("read aggregate report");
    let report: serde_json::Value = serde_json::from_str(&body).expect("parse aggregate report");
    let results = report["results"].as_array().expect("results array");
    assert_eq!(results.len(), 3);
    assert_eq!(results[0]["target_type"], "URL");
    assert_eq!(results[1]["target_type"], "TOKEN");
    assert_eq!(results[2]["target_type"], "DIR");
    assert!(results[2]["findings_count"].as_u64().unwrap_or(0) > 0);
}
