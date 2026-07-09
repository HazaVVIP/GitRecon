//! reporter.rs
//! Intelligence Report: colored terminal summary + report files to disk (JSON, SARIF, CSV, NDJSON, Markdown, HTML).
//! The only thing written to disk is the report file.

use std::path::Path;
use std::collections::HashMap;
use colored::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use crate::detect::DetectResult;
use crate::mapper::MapResult;
use crate::streamer::StreamResult;
use crate::text_utils::truncate_utf8;
use crate::validation;

#[derive(Clone)]
#[allow(dead_code)]
pub struct Reporter {
    pub no_color: bool,
}

#[allow(dead_code)]
impl Reporter {
    fn ai_summary(findings: &[crate::streamer::Finding]) -> (usize, HashMap<String, usize>) {
        let mut total = 0usize;
        let mut by_category: HashMap<String, usize> = HashMap::new();
        for f in findings {
            let (is_ai, cat, _) = crate::streamer::ai_metadata_for_finding(f);
            if !is_ai {
                continue;
            }
            total += 1;
            if let Some(c) = cat {
                *by_category.entry(c).or_insert(0) += 1;
            }
        }
        (total, by_category)
    }

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
        println!("{}", "  Enterprise Git Exposure Scanner".dimmed());
        println!("{}", format!("  {}", "─".repeat(53)).dimmed());
        println!();
    }

    pub fn print_detect(&self, r: &DetectResult) {
        let icon = if r.actionable() {
            "✔".green().bold().to_string()
        } else {
            "⚠".yellow().to_string()
        };
        let conf_str = format!("{} ({}%)", r.label, r.confidence);
        let conf_colored = self.conf_color(&r.label, &conf_str);

        let w = 58usize;
        println!("\n╔{}╗", "═".repeat(w));
        println!("║  {:<width$}║", "DETECTION", width = w - 2);
        println!("╚{}╝", "═".repeat(w));
        println!("│  {:<14}: {}", "Target", r.url);
        println!("│  {:<14}: {}", "Git URL", r.git_url.cyan());
        println!("│  {:<14}: {}  {}", "Confidence", conf_colored, icon);
        println!("│  {:<14}: {}", "Dir List",
                 if r.listing { "⚠  ON".yellow().to_string() } else { "OFF".to_string() });
        println!("│  {:<14}: {}", "Server", r.server);
        if let Some(ref br) = r.branch {
            println!("│  {:<14}: {}", "Branch", br);
        }
        if let Some(ref ru) = r.remote_url {
            println!("│  {:<14}: {}", "Remote", ru.yellow());
        }
        println!("│");
    }

    pub fn print_map(&self, m: &MapResult) {
        let all = m.all_sha1s();
        let w = 58usize;
        println!("\n╔{}╗", "═".repeat(w));
        println!("║  {:<width$}║", "RECONNAISSANCE", width = w - 2);
        println!("╚{}╝", "═".repeat(w));
        println!("│  {:<16}: {}", "SHA1 Objects", all.len().to_string().cyan());
        println!("│  {:<16}: {}", "Blobs (index)", m.blob_sha1s.len());
        println!("│  {:<16}: {}", "Commits/Trees", m.commit_sha1s.len());
        let branches_str = if m.branches.is_empty() { "—".to_string() }
                           else { m.branches[..m.branches.len().min(8)].join(", ") };
        println!("│  {:<16}: {}", "Branches", branches_str);
        if let Some(remote) = m.remote_urls.first() {
            if let Some(url) = remote.get("url") {
                println!("│  {:<16}: {}", "Remote", url.yellow());
            }
        }
        if !m.pack_sha1s.is_empty() {
            println!("│  {:<16}: {}", "Pack Files", m.pack_sha1s.len());
        }
        println!("│  {:<16}: {} (if --save)", "Est. Disk Size", m.size_human().green());
        println!("│");
    }

    pub fn print_stream_start(&self, total: usize) {
        let w = 58usize;
        println!("\n╔{}╗", "═".repeat(w));
        println!("║  {:<width$}║", "ANALYSIS", width = w - 2);
        println!("╚{}╝", "═".repeat(w));
        println!("│  Scanning {} objects in memory (no disk write)...",
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
        print!("\r  ▶  [{}] {:5.1}%  {}/{} objs  findings={}   ",
               bar_s, pct * 100.0, done, total, f_str);
        use std::io::Write;
        std::io::stdout().flush().ok();
    }

    pub fn print_stream_done(&self, r: &StreamResult) {
        println!(); // newline after progress bar
        println!("│  {:<16}: {}", "Blobs scanned", r.blobs_scanned);
        println!("│  {:<16}: {} KB", "Data processed", r.bytes_scanned / 1024);
        if r.files_saved > 0 || r.files_save_failed > 0 {
            println!("│  {:<16}: {}  Failed: {}", "Files saved", r.files_saved, r.files_save_failed);
        }
        println!("│  {:<16}: {:.1}s", "Elapsed", r.elapsed_s);
        // PERF-005: Display cache stats
        if r.cache_hits > 0 || r.cache_misses > 0 {
            let total_requests = r.cache_hits + r.cache_misses;
            let hit_rate = if total_requests > 0 {
                (r.cache_hits as f64 / total_requests as f64) * 100.0
            } else {
                0.0
            };
            println!("│  {:<16}: {}/{} ({:.1}%)", "Cache hits", r.cache_hits, total_requests, hit_rate);
            if let Some(ref stats) = r.cache_stats {
                println!("│  {:<16}: {} entries, {}", "Cache size", stats.total_entries, stats.size_human);
            }
        }
        println!("│");
    }

    /// Displays all deduplicated findings immediately after scanning, in card style.
    /// Shows a severity bar chart summary followed by individual finding cards.
    pub fn print_findings_summary(&self, findings: &[crate::streamer::Finding]) {
        let w = 58usize;
        let sev_order = |s: &str| match s {
            "CRITICAL" => 0,
            "HIGH"     => 1,
            "MEDIUM"   => 2,
            "LOW"      => 3,
            _          => 99,
        };

        let mut sorted = findings.to_vec();
        sorted.sort_by_key(|f| sev_order(&f.severity));

        let mut seen_keys = std::collections::HashSet::new();
        let deduped: Vec<_> = sorted.iter().filter(|f| {
            let key = (f.pattern_id.clone(), f.match_str.chars().take(40).collect::<String>());
            seen_keys.insert(key)
        }).collect();

        let crit  = deduped.iter().filter(|f| f.severity == "CRITICAL").count();
        let high  = deduped.iter().filter(|f| f.severity == "HIGH").count();
        let med   = deduped.iter().filter(|f| f.severity == "MEDIUM").count();
        let low   = deduped.iter().filter(|f| f.severity == "LOW").count();
        let total = deduped.len();

        println!("\n╔{}╗", "═".repeat(w));
        println!("║  {:<width$}║", "SCAN RESULTS", width = w - 2);
        println!("╚{}╝", "═".repeat(w));
        println!("│");

        if total == 0 {
            println!("│  {}  No secrets detected", "✔".green().bold());
            println!("│");
            return;
        }

        println!("│  Total Findings : {}", total.to_string().bold());
        println!("│");

        // Severity bar chart
        let bar_width = 20usize;
        let max_c = crit.max(high).max(med).max(low).max(1);
        let scale = bar_width as f64 / max_c as f64;
        let make_bar = |n: usize| "█".repeat((n as f64 * scale) as usize);

        if crit > 0 {
            println!("│  {}  {:<8}  {:>3}  {}",
                     "●".red().bold(), "CRITICAL".red().bold(), crit, make_bar(crit).red().bold());
        }
        if high > 0 {
            println!("│  {}  {:<8}  {:>3}  {}",
                     "●".yellow(), "HIGH".yellow(), high, make_bar(high).yellow());
        }
        if med > 0 {
            println!("│  {}  {:<8}  {:>3}  {}",
                     "●".bright_yellow(), "MEDIUM".bright_yellow(), med, make_bar(med).bright_yellow());
        }
        if low > 0 {
            println!("│  {}  {:<8}  {:>3}  {}",
                     "●".cyan(), "LOW".cyan(), low, make_bar(low).cyan());
        }
        println!("│");

        // Individual finding cards (no cap — all findings shown)
        for (i, f) in deduped.iter().enumerate() {
            let sev_colored = self.sev_color(&f.severity);
            let del_tag = if f.is_deleted { " · DELETED".dimmed().to_string() } else { String::new() };

            // Calculate right-side dashes: total line = 60 chars
            // "┌─[ #N · SEVERITY ]" + dashes + "┐"
            // prefix "┌─[" = 3, suffix "]" = 1, "┐" = 1 → fixed = 5 chars
            // header_plain used only for length, colored version in actual output
            let header_plain = format!(" #{} · {} ", i + 1, f.severity);
            let right_dashes = 55usize.saturating_sub(header_plain.len());
            println!("\n┌─[ #{} · {} ]{}┐",
                     (i + 1).to_string().bold(),
                     sev_colored,
                     "─".repeat(right_dashes));
            println!("│  {:<12}: {}{}", "Type", f.description, del_tag);
            println!("│  {:<12}: {}", "File",
                     format!("{}  ·  line {}", f.filename, f.line).cyan());
            let m = truncate_utf8(&f.match_str, 100);
            println!("│  {:<12}: {}", "Match", m);
            let ctx = truncate_utf8(&f.context, 120);
            println!("│  {:<12}: {}", "Context", ctx.dimmed());
            println!("└{}┘", "─".repeat(w));
        }
        println!();
    }

    /// Compact intelligence report footer shown after saving the report file.
    pub fn print_report(&self, _detect: &DetectResult, _map_r: &MapResult, stream_r: &StreamResult, report_path: &str) {
        let counts  = stream_r.severity_counts();
        let (ai_total, _) = Self::ai_summary(&stream_r.findings);
        let risk    = stream_r.risk_score();
        let risk_label = if risk >= 70 { "CRITICAL" } else if risk >= 40 { "HIGH" } else if risk >= 15 { "MEDIUM" } else { "CLEAR" };
        let risk_s  = format!("{}/100  {}", risk, risk_label);
        let risk_colored = self.risk_color(risk, &risk_s);

        let w = 58usize;
        println!("\n╔{}╗", "═".repeat(w));
        println!("║  {:<width$}║", "INTELLIGENCE REPORT", width = w - 2);
        println!("╚{}╝", "═".repeat(w));
        println!("│  {:<14}: {}", "Risk Score", risk_colored);
        println!("│  {:<14}: {}  [ {} {} {} ]",
                 "Findings",
                 stream_r.findings.len().to_string().bold(),
                 format!("CRIT:{}", counts["CRITICAL"]).red().bold(),
                 format!("HIGH:{}", counts["HIGH"]).yellow(),
                 format!("MED:{}", counts["MEDIUM"]).bright_yellow());
        println!("│  {:<14}: {}", "AI Findings", ai_total.to_string().magenta());
        if !stream_r.tech_stack.is_empty() {
            println!("│  {:<14}: {}", "Tech Stack", stream_r.tech_stack.join(", "));
        }
        if !stream_r.contributors.is_empty() {
            println!("│  {:<14}: {} found", "Developers", stream_r.contributors.len());
        }
        println!("│  {:<14}: {}  {}", "Report", report_path.green(), "✔".green().bold());
        println!("│");
        println!("└{}┘\n", "─".repeat(w));
    }

    pub fn print_summary(&self, target: &str, stream_r: &StreamResult, report_path: &str) {
        let risk_s  = format!("{}/100", stream_r.risk_score());
        let risk_colored = self.risk_color(stream_r.risk_score(), &risk_s);
        let w = 58usize;
        println!("\n╔{}╗", "═".repeat(w));
        println!("║  {:<width$}║", "COMPLETE", width = w - 2);
        println!("╚{}╝", "═".repeat(w));
        println!("│  {:<14}: {}", "Target", target);
        println!("│  {:<14}: {}", "Risk Score", risk_colored);
        println!("│  {:<14}: {} findings", "Secrets", stream_r.findings.len());
        println!("│  {:<14}: {}", "Report", report_path.green());
        println!("│");
        println!("└{}┘\n", "─".repeat(w));
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
            "version":   "3.2.0",
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
            let (ai_total, ai_categories) = Self::ai_summary(&s.findings);
            report["result"] = serde_json::json!({
                "risk_score":      s.risk_score(),
                "secrets_total":   s.findings.len(),
                "ai_findings_total": ai_total,
                "ai_category_counts": ai_categories,
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

    /// Save a JSON report for a `--token` scan.
    ///
    /// The report includes `"mode": "token"` at the top level so consumers can
    /// distinguish it from URL-based `.git` exposure reports.
    pub fn save_token_report(
        &self,
        path:       &str,
        login:      &str,
        repo_count: usize,
        stream_r:   &StreamResult,
    ) -> std::io::Result<()> {
        let now    = chrono::Utc::now().to_rfc3339();
        let counts = stream_r.severity_counts();
        let (ai_total, ai_categories) = Self::ai_summary(&stream_r.findings);
        let report = serde_json::json!({
            "tool":       "GitRecon",
            "version":    "3.2.0",
            "mode":       "token",
            "timestamp":  now,
            "token_user": login,
            "repo_count": repo_count,
            "result": {
                "risk_score":      stream_r.risk_score(),
                "secrets_total":   stream_r.findings.len(),
                "ai_findings_total": ai_total,
                "ai_category_counts": ai_categories,
                "severity_counts": counts,
                "tech_stack":      stream_r.tech_stack,
                "blobs_scanned":   stream_r.blobs_scanned,
                "bytes_scanned":   stream_r.bytes_scanned,
                "elapsed_s":       (stream_r.elapsed_s * 100.0).round() / 100.0,
                "findings":        stream_r.findings.iter().map(|f| f.to_dict()).collect::<Vec<_>>(),
            }
        });
        let parent = Path::new(path).parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let json_str = serde_json::to_string_pretty(&report)
            .map_err(std::io::Error::other)?;
        std::fs::write(path, json_str)
    }

    /// Print the final intelligence report for a `--token` scan to the terminal.
    pub fn print_token_report(
        &self,
        login:      &str,
        repo_count: usize,
        stream_r:   &StreamResult,
        report_path: &str,
    ) {
        let counts     = stream_r.severity_counts();
        let (ai_total, _) = Self::ai_summary(&stream_r.findings);
        let risk       = stream_r.risk_score();
        let risk_label = if risk >= 70 { "CRITICAL" } else if risk >= 40 { "HIGH" } else if risk >= 15 { "MEDIUM" } else { "CLEAR" };
        let risk_s     = format!("{}/100  {}", risk, risk_label);
        let risk_colored = self.risk_color(risk, &risk_s);

        let w = 58usize;
        println!("\n╔{}╗", "═".repeat(w));
        println!("║  {:<width$}║", "TOKEN SCAN REPORT", width = w - 2);
        println!("╚{}╝", "═".repeat(w));
        println!("│  {:<14}: {}", "GitHub User", login.cyan().bold());
        println!("│  {:<14}: {}", "Repos Scanned", repo_count);
        println!("│  {:<14}: {}", "Risk Score", risk_colored);
        println!("│  {:<14}: {}  [ {} {} {} ]",
                 "Findings",
                 stream_r.findings.len().to_string().bold(),
                 format!("CRIT:{}", counts["CRITICAL"]).red().bold(),
                 format!("HIGH:{}", counts["HIGH"]).yellow(),
                 format!("MED:{}", counts["MEDIUM"]).bright_yellow());
        println!("│  {:<14}: {}", "AI Findings", ai_total.to_string().magenta());
        println!("│  {:<14}: {} KB", "Data Processed", stream_r.bytes_scanned / 1024);
        println!("│  {:<14}: {:.1}s", "Elapsed", stream_r.elapsed_s);
        println!("│  {:<14}: {}  {}", "Report", report_path.green(), "✔".green().bold());
        println!("│");
        println!("└{}┘\n", "─".repeat(w));
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
                    "properties": {
                        "gitrecon": f.to_dict()
                    },
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
        // CSV schema:
        // file,line,severity,type,description,match,deleted,ai_related,ai_category,ai_tags
        let mut out = String::from("file,line,severity,type,description,match,deleted,ai_related,ai_category,ai_tags\n");
        if let Some(s) = stream_r {
            for f in &s.findings {
                // Get AI metadata first
                let (ai_related, ai_category, ai_tags) = crate::streamer::ai_metadata_for_finding(f);

                // SEC-005: CSV injection protection - sanitize all fields
                let sanitized_filename = validation::sanitize_csv_field(&f.filename);
                let sanitized_pattern = validation::sanitize_csv_field(&f.pattern_id);
                let sanitized_desc = validation::sanitize_csv_field(&f.description);
                let sanitized_match = validation::sanitize_csv_field(&f.match_str);
                let sanitized_ai_category = validation::sanitize_csv_field(&ai_category.unwrap_or_default());
                let sanitized_ai_tags = validation::sanitize_csv_field(&ai_tags.join("|"));

                let desc = sanitized_desc.replace('"', "\"\"");
                let m = sanitized_match.replace('"', "\"\"");

                out.push_str(&format!(
                    "{},{},{},{},\"{}\",\"{}\",{},{},\"{}\",\"{}\"\n",
                    sanitized_filename, f.line, f.severity, sanitized_pattern, desc, m, f.is_deleted, ai_related, sanitized_ai_category, sanitized_ai_tags
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
        out.push_str("| Severity | Type | File | Line | AI | Match |\n");
        out.push_str("|----------|------|------|------|----|-------|\n");
        if let Some(s) = stream_r {
            for f in &s.findings {
                let emoji = match f.severity.as_str() {
                    "CRITICAL" => "🔴",
                    "HIGH"     => "🟡",
                    "MEDIUM"   => "🟠",
                    "LOW"      => "🔵",
                    _          => "⚪",
                };
                let m = truncate_utf8(&f.match_str, 60);
                let (ai_related, ai_category, _) = crate::streamer::ai_metadata_for_finding(f);
                let ai_col = if ai_related {
                    format!("✅ {}", ai_category.unwrap_or_else(|| "ai".to_string()))
                } else {
                    "—".to_string()
                };
                out.push_str(&format!(
                    "| {} {} | {} | {} | {} | {} | `{}` |\n",
                    emoji, f.severity, f.pattern_id, f.filename, f.line, ai_col, m
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
                let m = truncate_utf8(&f.match_str, 80);
                let (ai_related, ai_category, _) = crate::streamer::ai_metadata_for_finding(f);
                let ai_col = if ai_related {
                    ai_category.unwrap_or_else(|| "ai".to_string())
                } else {
                    "no".to_string()
                };
                rows.push_str(&format!(
                    "<tr><td style='color:{}'>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>\n",
                    color, f.severity, f.pattern_id, f.filename, f.line, ai_col, m
                ));
            }
        }
        let html = format!(r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>GitRecon Report</title>
<style>body{{font-family:sans-serif;margin:2em}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:8px;text-align:left}}th{{background:#222;color:#fff}}</style>
</head><body>
<h1>GitRecon Report</h1>
<p><strong>Target:</strong> {}</p>
<table><thead><tr><th>Severity</th><th>Type</th><th>File</th><th>Line</th><th>AI</th><th>Match</th></tr></thead>
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::streamer::{Finding, StreamResult};
    use std::path::PathBuf;

    struct TempDirGuard {
        path: PathBuf,
    }

    impl TempDirGuard {
        fn new(path: PathBuf) -> Self {
            let _ = std::fs::create_dir_all(&path);
            Self { path }
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn unicode_finding() -> Finding {
        Finding {
            filename: "/tmp/demo.rs".to_string(),
            line: 42,
            pattern_id: "jwt_secret".to_string(),
            description: "JWT Secret".to_string(),
            severity: "CRITICAL".to_string(),
            match_str: "secret🔐─你好🌍".repeat(16),
            context: "const ECOMM_JWT_SECRET = process.env.ECOMM_JWT_SECRET || \"密钥─🔒\"".repeat(8),
            is_deleted: false,
            commit_sha1: Some("a".repeat(40)),
            confidence_adjustment: None,
        }
    }

    fn unicode_stream_result() -> StreamResult {
        StreamResult {
            findings: vec![unicode_finding()],
            contributors: vec![],
            tech_stack: vec![],
            commit_count: 0,
            blobs_scanned: 1,
            blobs_failed: 0,
            bytes_scanned: 10,
            elapsed_s: 0.1,
            files_saved: 0,
            files_save_failed: 0,
            rate_limit_allowed: 0,
            rate_limit_dropped: 0,
            rate_limit_wait_ms: 0,
            cache_hits: 0,
            cache_misses: 0,
            cache_stats: None,
        }
    }

    #[test]
    fn print_findings_summary_handles_unicode_without_panic() {
        let rep = Reporter::new(true);
        let findings = vec![unicode_finding()];
        rep.print_findings_summary(&findings);
    }

    #[test]
    fn save_markdown_and_html_handle_unicode_without_panic() {
        let rep = Reporter::new(true);
        let stream = unicode_stream_result();
        let tmp = std::env::temp_dir().join(format!("gitrecon_reporter_test_{}", std::process::id()));
        let _guard = TempDirGuard::new(tmp.clone());

        let md_path = tmp.join("report.md");
        let html_path = tmp.join("report.html");
        let md_str = md_path.to_string_lossy().to_string();
        let html_str = html_path.to_string_lossy().to_string();

        rep.save_markdown(&md_str, "target", Some(&stream)).expect("save markdown");
        rep.save_html(&html_str, "target", Some(&stream)).expect("save html");
    }
}
