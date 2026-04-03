//! reporter.rs
//! Phase 4 — Report: colored terminal summary + JSON to disk.
//! The only thing written to disk is the JSON report file.

use std::path::Path;
use colored::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use crate::detect::DetectResult;
use crate::mapper::MapResult;
use crate::streamer::StreamResult;

#[derive(Clone)]
#[allow(dead_code)]
pub struct Reporter {
    pub no_color: bool,
}

#[allow(dead_code)]
impl Reporter {
    pub fn new(no_color: bool) -> Self {
        if no_color {
            colored::control::set_override(false);
        }
        Self { no_color }
    }

    pub fn banner(&self) {
        let art = r#"
  ██████╗ ██╗████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔════╝ ██║╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██║  ███╗██║   ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██║   ██║██║   ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ╚██████╔╝██║   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
"#;
        println!("{}", art.cyan().bold());
        println!("{}", "  Git Exposure · Streaming Scanner · No disk required".dimmed());
        println!("{}", format!("  {}", "─".repeat(53)).dimmed());
        println!();
    }

    pub fn print_detect(&self, r: &DetectResult) {
        let icon = if r.actionable() { "✅" } else { "⚠️ " };
        let conf_str = format!("{} ({}%)", r.label, r.confidence);
        let conf_colored = self.conf_color(&r.label, &conf_str);

        println!("\n{}", "─".repeat(58).bold());
        println!("{}", "  [1/4] DETECTION".bold());
        println!("{}", "─".repeat(58));
        println!("  {}: {}", "Target    ".bold(), r.url);
        println!("  {}: {}", "Git URL   ".bold(), r.git_url.cyan());
        println!("  {}: {}  {}", "Confidence".bold(), conf_colored, icon);
        println!("  {}: {}", "Dir List  ".bold(),
                 if r.listing { "⚠️  ON".yellow().to_string() } else { "OFF".to_string() });
        println!("  {}: {}", "Server    ".bold(), r.server);
        if let Some(ref br) = r.branch {
            println!("  {}: {}", "Branch    ".bold(), br);
        }
        if let Some(ref ru) = r.remote_url {
            println!("  {}: {}", "Remote    ".bold(), ru.yellow());
        }
        println!();
    }

    pub fn print_map(&self, m: &MapResult) {
        let all = m.all_sha1s();
        println!("  {}", "[2/4] MAP".bold());
        println!("  {}", "─".repeat(50));
        println!("  SHA1s found   : {}", all.len().to_string().cyan());
        println!("  Blobs (index) : {}", m.blob_sha1s.len());
        println!("  Commits/trees : {}", m.commit_sha1s.len());
        let branches_str = if m.branches.is_empty() { "—".to_string() }
                           else { m.branches[..m.branches.len().min(8)].join(", ") };
        println!("  Branches      : {}", branches_str);
        if let Some(remote) = m.remote_urls.first() {
            if let Some(url) = remote.get("url") {
                println!("  Remote        : {}", url.yellow());
            }
        }
        if !m.pack_sha1s.is_empty() {
            println!("  Pack files    : {}", m.pack_sha1s.len());
        }
        println!("  Est. disk size: {} (if --save)", m.size_human().green());
        println!();
    }

    pub fn print_stream_start(&self, total: usize) {
        println!("  {}", "[3/4] STREAMING & SCANNING".bold());
        println!("  {}", "─".repeat(50));
        println!("  Scanning {} objects in memory (no disk write)...",
                 total.to_string().cyan());
    }

    pub fn progress_bar(&self, done: usize, total: usize, findings: usize) {
        if total == 0 { return; }
        let pct = done as f64 / total as f64;
        let bar = (pct * 30.0) as usize;
        let bar_s = format!("{}{}", "█".repeat(bar), "░".repeat(30 - bar));
        let f_str = if findings > 0 {
            findings.to_string().red().bold().to_string()
        } else {
            findings.to_string().green().to_string()
        };
        print!("\r  [{}] {:5.1}%  {}/{} objs  findings={}   ",
               bar_s, pct * 100.0, done, total, f_str);
        use std::io::Write;
        std::io::stdout().flush().ok();
    }

    pub fn print_stream_done(&self, r: &StreamResult) {
        println!(); // newline after progress bar
        println!("  Blobs scanned : {}", r.blobs_scanned);
        println!("  Data processed: {:} KB", r.bytes_scanned / 1024);
        if r.files_saved > 0 || r.files_save_failed > 0 {
            println!("  Files saved   : {}  Failed: {}", r.files_saved, r.files_save_failed);
        }
        println!("  Elapsed       : {:.1}s", r.elapsed_s);
        println!();
    }

    pub fn print_report(&self, _detect: &DetectResult, _map_r: &MapResult, stream_r: &StreamResult) {
        let counts  = stream_r.severity_counts();
        let risk    = stream_r.risk_score();
        let risk_s  = format!("{}/100", risk);
        let risk_colored = self.risk_color(risk, &risk_s);

        println!("  {}", "[4/4] FINDINGS REPORT".bold());
        println!("  {}", "─".repeat(50));
        println!("  Risk Score : {}", risk_colored);
        println!("  Secrets    : {}  [ {} {} {} ]",
                 stream_r.findings.len().to_string().bold(),
                 format!("CRIT:{}", counts["CRITICAL"]).red().bold(),
                 format!("HIGH:{}", counts["HIGH"]).yellow(),
                 format!("MED:{}", counts["MEDIUM"]).bright_yellow());

        if !stream_r.tech_stack.is_empty() {
            println!("  Tech Stack : {}", stream_r.tech_stack.join(", "));
        }
        if !stream_r.contributors.is_empty() {
            println!("  Developers : {} found", stream_r.contributors.len());
            for c in stream_r.contributors.iter().take(4) {
                println!("    · {} <{}>", c.name, c.email.cyan());
            }
        }
        println!("  Commits    : ~{}", stream_r.commit_count);

        // Deduplicate + sort by severity
        let sev_order = |s: &str| match s {
            "CRITICAL" => 0,
            "HIGH"     => 1,
            "MEDIUM"   => 2,
            "LOW"      => 3,
            _          => 99,
        };

        let mut sorted = stream_r.findings.clone();
        sorted.sort_by_key(|f| sev_order(&f.severity));

        let mut seen_keys = std::collections::HashSet::new();
        let deduped: Vec<_> = sorted.iter().filter(|f| {
            let key = (f.pattern_id.clone(), f.match_str.chars().take(40).collect::<String>());
            seen_keys.insert(key)
        }).collect();

        if !deduped.is_empty() {
            println!("\n  {} unique):", format!("Secret Findings ({}", deduped.len()).bold());
            for (i, f) in deduped.iter().take(25).enumerate() {
                let sev_colored = self.sev_color(&f.severity);
                let del_tag = if f.is_deleted { " [DELETED]".dimmed().to_string() } else { String::new() };
                println!("\n  {} [{}] {}{}", format!("#{}", i + 1).bold(), sev_colored, f.description, del_tag);
                println!("     File   : {}  line {}", f.filename.cyan(), f.line);
                let m = &f.match_str[..f.match_str.len().min(100)];
                println!("     Match  : {}", m);
                let ctx = &f.context[..f.context.len().min(120)];
                println!("     Context: {}", ctx.dimmed());
            }
            if deduped.len() > 25 {
                println!("\n  ... +{} more findings in JSON report", deduped.len() - 25);
            }
        }
    }

    pub fn print_summary(&self, target: &str, stream_r: &StreamResult, report_path: &str) {
        let risk_s  = format!("{}/100", stream_r.risk_score());
        let risk_colored = self.risk_color(stream_r.risk_score(), &risk_s);
        println!("\n{}", "═".repeat(58));
        println!("{}  |  {}", "  DONE".bold(), target);
        println!("{}", "═".repeat(58));
        println!("  Risk Score : {}", risk_colored);
        println!("  Secrets    : {} findings (0 bytes written to disk)",
                 stream_r.findings.len());
        println!("  Report     : {}", report_path.green());
        println!("{}\n", "═".repeat(58));
    }

    pub fn save_json(
        &self,
        path: &str,
        target: &str,
        detect: Option<&DetectResult>,
        map_r: Option<&MapResult>,
        stream_r: Option<&StreamResult>,
    ) -> std::io::Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let mut report = serde_json::json!({
            "tool":      "GitRecon",
            "version":   "3.1.0",
            "timestamp": now,
            "target":    target,
        });

        if let Some(d) = detect {
            report["detection"] = serde_json::json!({
                "git_url":    d.git_url,
                "git_path":   d.git_url.strip_prefix(target).unwrap_or("").trim_start_matches('/'),
                "confidence": d.confidence,
                "label":      d.label,
                "listing":    d.listing,
                "server":     d.server,
                "branch":     d.branch,
                "remote_url": d.remote_url,
            });
        }

        if let Some(m) = map_r {
            let all = m.all_sha1s();
            report["map"] = serde_json::json!({
                "total_sha1s":     all.len(),
                "blob_sha1s":      m.blob_sha1s.len(),
                "commit_sha1s":    m.commit_sha1s.len(),
                "branches":        m.branches,
                "remote_urls":     m.remote_urls,
                "pack_count":      m.pack_sha1s.len(),
                "estimated_files": m.estimated_files,
                "estimated_bytes": m.estimated_bytes,
                "size_human":      m.size_human(),
            });
        }

        if let Some(s) = stream_r {
            let counts = s.severity_counts();
            report["result"] = serde_json::json!({
                "risk_score":      s.risk_score(),
                "secrets_total":   s.findings.len(),
                "severity_counts": counts,
                "tech_stack":      s.tech_stack,
                "commit_count":    s.commit_count,
                "contributors":    s.contributors.iter().take(50).map(|c| {
                    serde_json::json!({"name": c.name, "email": c.email})
                }).collect::<Vec<_>>(),
                "blobs_scanned":   s.blobs_scanned,
                "bytes_scanned":   s.bytes_scanned,
                "elapsed_s":       (s.elapsed_s * 100.0).round() / 100.0,
                "findings":        s.findings.iter().map(|f| f.to_dict()).collect::<Vec<_>>(),
            });
        }

        let parent = Path::new(path).parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let json_str = serde_json::to_string_pretty(&report)
            .map_err(std::io::Error::other)?;
        std::fs::write(path, json_str)
    }

    // ── Color helpers ──────────────────────────────

    fn sev_color(&self, sev: &str) -> ColoredString {
        match sev {
            "CRITICAL" => sev.red().bold(),
            "HIGH"     => sev.yellow(),
            "MEDIUM"   => sev.bright_yellow(),
            "LOW"      => sev.cyan(),
            _          => sev.normal(),
        }
    }

    fn conf_color(&self, label: &str, s: &str) -> ColoredString {
        match label {
            "CONFIRMED" => s.red().bold(),
            "HIGH"      => s.yellow(),
            "MEDIUM"    => s.bright_yellow(),
            "LOW"       => s.cyan(),
            _           => s.dimmed(),
        }
    }

    fn risk_color(&self, score: u32, s: &str) -> ColoredString {
        if score >= 70      { s.red().bold() }
        else if score >= 40 { s.yellow() }
        else if score >= 15 { s.bright_yellow() }
        else                { s.green() }
    }

    // O-2: SARIF 2.1.0 output format
    pub fn save_sarif(&self, path: &str, _target: &str, stream_r: Option<&StreamResult>) -> std::io::Result<()> {
        let mut rules = Vec::new();
        let mut results = Vec::new();

        if let Some(s) = stream_r {
            for f in &s.findings {
                let level = match f.severity.as_str() {
                    "CRITICAL" | "HIGH" => "error",
                    "MEDIUM" => "warning",
                    _ => "note",
                };
                rules.push(serde_json::json!({
                    "id": f.pattern_id,
                    "name": f.pattern_id,
                    "shortDescription": {"text": f.description}
                }));
                results.push(serde_json::json!({
                    "ruleId": f.pattern_id,
                    "level": level,
                    "message": {"text": f.description},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.filename},
                            "region": {"startLine": f.line}
                        }
                    }]
                }));
            }
        }

        let sarif = serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "GitRecon", "version": "3.2.0", "rules": rules}},
                "results": results
            }]
        });

        let parent = Path::new(path).parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let json_str = serde_json::to_string_pretty(&sarif).map_err(std::io::Error::other)?;
        std::fs::write(path, json_str)
    }

    // O-3: CSV output format
    pub fn save_csv(&self, path: &str, stream_r: Option<&StreamResult>) -> std::io::Result<()> {
        let parent = Path::new(path).parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let mut out = String::from("file,line,severity,type,description,match,deleted\n");
        if let Some(s) = stream_r {
            for f in &s.findings {
                let m = f.match_str.replace('"', "\"\"");
                let desc = f.description.replace('"', "\"\"");
                out.push_str(&format!(
                    "{},{},{},{},\"{}\",\"{}\",{}\n",
                    f.filename, f.line, f.severity, f.pattern_id, desc, m, f.is_deleted
                ));
            }
        }
        std::fs::write(path, out)
    }

    // O-3: NDJSON output format
    pub fn save_ndjson(&self, path: &str, stream_r: Option<&StreamResult>) -> std::io::Result<()> {
        let parent = Path::new(path).parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let mut out = String::new();
        if let Some(s) = stream_r {
            for f in &s.findings {
                if let Ok(line) = serde_json::to_string(&f.to_dict()) {
                    out.push_str(&line);
                    out.push('\n');
                }
            }
        }
        std::fs::write(path, out)
    }

    // O-3: Markdown output format
    pub fn save_markdown(&self, path: &str, target: &str, stream_r: Option<&StreamResult>) -> std::io::Result<()> {
        let parent = Path::new(path).parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let mut out = format!("# GitRecon Report\n\n**Target:** {}\n\n", target);
        out.push_str("| Severity | Type | File | Line | Match |\n");
        out.push_str("|----------|------|------|------|-------|\n");
        if let Some(s) = stream_r {
            for f in &s.findings {
                let emoji = match f.severity.as_str() {
                    "CRITICAL" => "🔴",
                    "HIGH"     => "🟡",
                    "MEDIUM"   => "🟠",
                    "LOW"      => "🔵",
                    _          => "⚪",
                };
                let m = &f.match_str[..f.match_str.len().min(60)];
                out.push_str(&format!(
                    "| {} {} | {} | {} | {} | `{}` |\n",
                    emoji, f.severity, f.pattern_id, f.filename, f.line, m
                ));
            }
        }
        std::fs::write(path, out)
    }

    // O-3: HTML output format
    pub fn save_html(&self, path: &str, target: &str, stream_r: Option<&StreamResult>) -> std::io::Result<()> {
        let parent = Path::new(path).parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let mut rows = String::new();
        if let Some(s) = stream_r {
            for f in &s.findings {
                let color = match f.severity.as_str() {
                    "CRITICAL" => "#ff4444",
                    "HIGH"     => "#ff8800",
                    "MEDIUM"   => "#ffbb00",
                    "LOW"      => "#4488ff",
                    _          => "#888888",
                };
                let m = &f.match_str[..f.match_str.len().min(80)];
                rows.push_str(&format!(
                    "<tr><td style='color:{}'>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>\n",
                    color, f.severity, f.pattern_id, f.filename, f.line, m
                ));
            }
        }
        let html = format!(r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>GitRecon Report</title>
<style>body{{font-family:sans-serif;margin:2em}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:8px;text-align:left}}th{{background:#222;color:#fff}}</style>
</head><body>
<h1>GitRecon Report</h1>
<p><strong>Target:</strong> {}</p>
<table><thead><tr><th>Severity</th><th>Type</th><th>File</th><th>Line</th><th>Match</th></tr></thead>
<tbody>{}</tbody></table>
</body></html>"#, target, rows);
        std::fs::write(path, html)
    }

    // O-4: Webhook integration
    fn compute_hmac_sha256(key: &str, data: &str) -> String {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC init");
        mac.update(data.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    pub async fn send_webhook(
        &self,
        url: &str,
        secret: Option<&str>,
        body: &str,
        client: &crate::http_client::HttpClient,
    ) -> bool {
        let mut extra_headers = Vec::new();
        if let Some(key) = secret {
            let sig = Self::compute_hmac_sha256(key, body);
            extra_headers.push(("X-GitRecon-Signature".to_string(), sig));
        }
        let resp = client.post(url, body, &extra_headers).await;
        resp.status >= 200 && resp.status < 300
    }
}
