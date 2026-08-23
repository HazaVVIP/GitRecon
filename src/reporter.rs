//! reporter.rs
//! Intelligence Report: colored terminal summary + report files to disk (JSON, SARIF, CSV, NDJSON, Markdown, HTML).
//! The only thing written to disk is the report file.

use crate::detect::DetectResult;
use crate::layout;
use crate::mapper::MapResult;
use crate::outcome::TargetOutcome;
use crate::streamer::StreamResult;
use crate::text_utils::truncate_utf8;
use crate::ui::colors::ColorScheme;
use crate::ui::{self, BannerStyle};
use crate::validation;
use colored::*;
use hmac::{Hmac, Mac};
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use sha2::Sha256;
use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::Path;

/// Build the canonical report filename for a target and output format.
pub(crate) fn build_report_path(output: &str, report_name: &str, format: &str) -> String {
    let extension = match format {
        "sarif" => "sarif",
        "csv" => "csv",
        "ndjson" => "ndjson",
        "md" => "md",
        "html" => "html",
        _ => "json",
    };
    format!("{}/{}_report.{}", output, report_name, extension)
}

pub(crate) fn save_aggregate_report(
    path: &str,
    total_targets: usize,
    results: &[TargetOutcome],
) -> std::io::Result<()> {
    let body = serde_json::to_string_pretty(&serde_json::json!({
        "tool": "GitRecon",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "total_targets": total_targets,
        "scanned_targets": results.len(),
        "results": results,
    }))
    .unwrap_or_default();
    std::fs::write(path, body)
}

// ════════════════════════════════════════════════
// OUTPUT ESCAPING HELPERS (Sprint 2)
// ════════════════════════════════════════════════
//
// Filenames, match strings, and pattern IDs land in reports from **attacker-controlled**
// repo content — the repo owner can plant `<script>` in a filename, backticks in a secret
// value, pipe chars to break a Markdown table, etc. Every writer that emits these fields
// into a document format MUST route them through the appropriate escape function first.

/// HTML escape covering the five characters required to be safe in element text AND
/// attribute values (single quote handled too even though our template only uses
/// double-quoted attributes — belt & suspenders for future edits).
pub(crate) fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '=' => out.push_str("&#61;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Markdown table cell escape. Table cells break on `|` and `\n`; backticks would close
/// our inline-code wrapper; `[..](..)` becomes a link. We defang everything.
pub(crate) fn md_cell_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '|' => out.push_str("\\|"),
            '`' => out.push_str("\\`"),
            '[' => out.push_str("\\["),
            ']' => out.push_str("\\]"),
            '\\' => out.push_str("\\\\"),
            '\n' | '\r' => out.push(' '),
            _ => out.push(ch),
        }
    }
    out
}

/// RFC 4180 CSV field: always wrap in double quotes, escape internal `"` as `""`.
/// Also strips leading `= + - @ \t \r` which trigger formula execution in
/// Excel/LibreOffice/Numbers (CVE-2014-3524-style). `validation::sanitize_csv_field`
/// handles the formula prefix — we ensure the quoting on top of it.
pub(crate) fn csv_field(s: &str) -> String {
    let sanitized = validation::sanitize_csv_field(s);
    format!("\"{}\"", sanitized.replace('"', "\"\""))
}

/// Write a report file with restrictive permissions on Unix (Sprint 2, S2.9).
///
/// Report bodies contain matched secret plaintext (API keys, cloud tokens, DB
/// passwords, PEM material). The default umask on shared Linux hosts (e.g. VPS,
/// jump boxes, red-team boxes) creates files with mode 0644 → readable by every
/// other UID on the box. This helper creates the file with mode 0600 (owner
/// read/write only) BEFORE any content is written, closing that window.
///
/// On non-Unix platforms this falls back to `std::fs::write` — the OS ACLs are
/// governed by NTFS inheritance which we can't tighten portably here.
pub(crate) fn write_report_secure<P: AsRef<Path>>(path: P, contents: &[u8]) -> std::io::Result<()> {
    let path = path.as_ref();
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents)?;
        file.sync_data()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct Reporter {
    pub no_color: bool,
    pub theme: ui::theme::Theme,
}

/// Sprint 4 (S4.3): should we render live progress?
///
/// A progress bar written to a pipe corrupts the captured output with `\r` cursor
/// resets and spinner frames — reviewers see garbled logs. We hide the bar whenever
/// stdout is not an interactive terminal (piped, redirected, running under CI or
/// `--pipe` mode which redirects stdout to a JSON stream).
fn interactive_progress_enabled() -> bool {
    std::io::stdout().is_terminal()
}

/// Wrap a `ProgressBar` so it renders only when stdout is an interactive terminal.
/// When hidden, all `ProgressBar::set_position` / `inc` calls become cheap no-ops.
fn maybe_hidden(pb: ProgressBar) -> ProgressBar {
    if !interactive_progress_enabled() {
        pb.set_draw_target(ProgressDrawTarget::hidden());
    }
    pb
}

/// Context used by the shared report dispatcher to preserve mode-specific JSON schemas.
pub enum ReportContext<'a> {
    Exposure {
        target: &'a str,
        detect: &'a DetectResult,
        map: &'a MapResult,
    },
    Token {
        login: &'a str,
        repo_count: usize,
    },
    Stream {
        target: &'a str,
    },
}

#[allow(dead_code)]
impl Reporter {
    /// Save a scan result using the selected format and mode-aware JSON context.
    pub fn save_scan_report(
        &self,
        path: &str,
        format: &str,
        name: &str,
        stream: &StreamResult,
        context: ReportContext<'_>,
    ) -> std::io::Result<()> {
        match format {
            "sarif" => self.save_sarif(path, name, Some(stream)),
            "csv" => self.save_csv(path, Some(stream)),
            "ndjson" => self.save_ndjson(path, Some(stream)),
            "md" => self.save_markdown(path, name, Some(stream)),
            "html" => self.save_html(path, name, Some(stream)),
            _ => match context {
                ReportContext::Exposure {
                    target,
                    detect,
                    map,
                } => self.save_json(path, target, Some(detect), Some(map), Some(stream)),
                ReportContext::Token { login, repo_count } => {
                    self.save_token_report(path, login, repo_count, stream)
                }
                ReportContext::Stream { target } => {
                    self.save_json(path, target, None, None, Some(stream))
                }
            },
        }
    }

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

    pub fn new(no_color: bool, theme: &ui::theme::Theme) -> Self {
        if no_color {
            colored::control::set_override(false);
        }
        Self {
            no_color,
            theme: theme.clone(),
        }
    }

    pub fn banner(&self) {
        // Use theme's banner style instead of defaulting to Full
        let style = match self.theme.banner_style {
            ui::theme::BannerStyle::Minimal => BannerStyle::Mini, // Map Minimal -> Mini
            ui::theme::BannerStyle::Standard => BannerStyle::Full, // Map Standard -> Full
            ui::theme::BannerStyle::Full => BannerStyle::Full,
            ui::theme::BannerStyle::None => BannerStyle::None,
        };
        self.banner_with_style(style);
    }

    /// Display banner with specified style
    pub fn banner_with_style(&self, style: BannerStyle) {
        let banner = ui::Banner::new().style(style).colored(!self.no_color);
        banner.display_with_style(style);
    }

    pub fn print_detect(&self, r: &DetectResult) {
        let icon = if r.actionable() {
            "✔".green().bold().to_string()
        } else {
            "⚠".yellow().to_string()
        };
        let conf_str = format!("{} ({}%)", r.label, r.confidence);
        let conf_colored = ColorScheme::confidence(&r.label, &conf_str);

        let w = layout::calculate_box_width(60, layout::get_terminal_width());
        println!("\n╔{}╗", "═".repeat(w));
        println!("║  {:<width$}║", "DETECTION", width = w - 2);
        println!("╚{}╝", "═".repeat(w));
        println!("│  {:<14}: {}", "Target", r.url);
        println!("│  {:<14}: {}", "Git URL", r.git_url.cyan());
        println!("│  {:<14}: {}  {}", "Confidence", conf_colored, icon);
        println!(
            "│  {:<14}: {}",
            "Dir List",
            if r.listing {
                "⚠  ON".yellow().to_string()
            } else {
                "OFF".to_string()
            }
        );
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
        let w = layout::calculate_box_width(60, layout::get_terminal_width());
        println!("\n╔{}╗", "═".repeat(w));
        println!("║  {:<width$}║", "RECONNAISSANCE", width = w - 2);
        println!("╚{}╝", "═".repeat(w));
        println!(
            "│  {:<16}: {}",
            "SHA1 Objects",
            all.len().to_string().cyan()
        );
        println!("│  {:<16}: {}", "Blobs (index)", m.blob_sha1s.len());
        println!("│  {:<16}: {}", "Commits/Trees", m.commit_sha1s.len());
        let branches_str = if m.branches.is_empty() {
            "—".to_string()
        } else {
            m.branches[..m.branches.len().min(8)].join(", ")
        };
        println!("│  {:<16}: {}", "Branches", branches_str);
        if let Some(remote) = m.remote_urls.first() {
            if let Some(url) = remote.get("url") {
                println!("│  {:<16}: {}", "Remote", url.yellow());
            }
        }
        if !m.pack_sha1s.is_empty() {
            println!("│  {:<16}: {}", "Pack Files", m.pack_sha1s.len());
        }
        println!(
            "│  {:<16}: {} (if --save)",
            "Est. Disk Size",
            m.size_human().green()
        );
        println!("│");
    }

    pub fn print_stream_start(&self, total: usize) {
        let w = layout::calculate_box_width(60, layout::get_terminal_width());
        println!("\n╔{}╗", "═".repeat(w));
        println!("║  {:<width$}║", "ANALYSIS", width = w - 2);
        println!("╚{}╝", "═".repeat(w));
        println!(
            "│  Scanning {} objects in memory (no disk write)...",
            total.to_string().cyan()
        );
    }

    /// Create a new MultiProgress instance for multi-stage progress tracking.
    /// Returns an indicatif MultiProgress that can manage multiple progress bars.
    ///
    /// # Example
    /// ```ignore
    /// let multi = create_multi_stage_progress();
    /// let pb1 = multi.add(ProgressBar::new(100));
    /// let pb2 = multi.add(ProgressBar::new(50));
    /// ```
    pub fn create_multi_stage_progress() -> MultiProgress {
        // Sprint 4 (S4.3): hidden target when stdout is not a terminal so the
        // multi-progress internal writer does not spam \r sequences into a pipe.
        if interactive_progress_enabled() {
            MultiProgress::new()
        } else {
            MultiProgress::with_draw_target(ProgressDrawTarget::hidden())
        }
    }

    /// Enhanced progress bar with ETA and throughput using indicatif.
    /// Shows spinner, elapsed time, progress bar, position/length, ETA, and items per second.
    ///
    /// This version creates a new ProgressBar each call and returns it for the caller
    /// to manage. For multi-stage operations, use `create_multi_stage_progress`.
    ///
    /// # Parameters
    /// - `done`: Current completed count
    /// - `total`: Total items to process
    /// - `findings`: Number of findings detected
    ///
    /// # Returns
    /// A configured ProgressBar that the caller should increment with `.inc(1)` or `.set_position()`
    ///
    /// # Example
    /// ```ignore
    /// let pb = reporter.progress_bar(0, 1000, 0);
    /// for i in 0..1000 {
    ///     pb.inc(1);
    ///     // ... work ...
    /// }
    /// pb.finish();
    /// ```
    pub fn progress_bar(&self, done: usize, total: usize, findings: usize) -> ProgressBar {
        if total == 0 {
            // Return a dummy/no-op bar for zero total
            let pb = ProgressBar::hidden();
            return pb;
        }

        let pb = ProgressBar::new(total as u64);
        pb.set_position(done as u64);

        // Template: {spinner} {elapsed} {bar} {pos}/{len} ETA: {eta} [{per_sec}]
        let style = ProgressStyle::with_template(
            "{spinner} {elapsed} {bar} {pos}/{len} ETA: {eta} [{per_sec}]",
        )
        .unwrap()
        .progress_chars("=> ")
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]);

        pb.set_style(style);

        // Add findings prefix if any
        if findings > 0 {
            pb.set_prefix(format!("FINDINGS: {}", findings.to_string().red().bold()));
        }

        // Sprint 4 (S4.3): hide when stdout is piped/redirected so captured output
        // stays clean.
        maybe_hidden(pb)
    }

    /// Simplified legacy progress bar (for backward compatibility).
    /// This maintains the original inline progress display behavior.
    pub fn progress_bar_legacy(&self, done: usize, total: usize, findings: usize) {
        if total == 0 {
            return;
        }
        let pct = done as f64 / total as f64;
        let bar = (pct * 30.0) as usize;
        let bar_s = format!("{}{}", "█".repeat(bar), "░".repeat(30 - bar));
        let f_str = if findings > 0 {
            findings.to_string().red().bold().to_string()
        } else {
            findings.to_string().green().to_string()
        };
        print!(
            "\r  ▶  [{}] {:5.1}%  {}/{} objs  findings={}   ",
            bar_s,
            pct * 100.0,
            done,
            total,
            f_str
        );
        use std::io::Write;
        std::io::stdout().flush().ok();
    }

    /// Create a styled progress bar for multi-stage operations.
    /// Returns a ProgressBar configured with the GitRecon style template.
    ///
    /// # Parameters
    /// - `total`: Total items to process
    /// - `prefix`: Optional prefix text (e.g., stage name)
    ///
    /// # Returns
    /// A configured ProgressBar ready for use
    pub fn create_progress_bar(&self, total: usize, prefix: Option<&str>) -> ProgressBar {
        let pb = ProgressBar::new(total as u64);

        let style = ProgressStyle::with_template(
            "{spinner} {elapsed} {bar} {pos}/{len} ETA: {eta} [{per_sec}]",
        )
        .unwrap()
        .progress_chars("=> ")
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]);

        pb.set_style(style);

        if let Some(p) = prefix {
            pb.set_prefix(p.to_string());
        }

        // Sprint 4 (S4.3): hide on non-TTY stdout.
        maybe_hidden(pb)
    }

    /// Create a progress bar with custom styling options.
    ///
    /// # Parameters
    /// - `total`: Total items to process
    /// - `template`: Custom progress template (defaults to GitRecon style if None)
    /// - `prefix`: Optional prefix text
    /// - `message`: Optional static message
    ///
    /// # Returns
    /// A configured ProgressBar
    pub fn create_custom_progress_bar(
        &self,
        total: usize,
        template: Option<&str>,
        prefix: Option<&str>,
        message: Option<&str>,
    ) -> ProgressBar {
        let pb = ProgressBar::new(total as u64);

        let tmpl =
            template.unwrap_or("{spinner} {elapsed} {bar} {pos}/{len} ETA: {eta} [{per_sec}]");
        let style = ProgressStyle::with_template(tmpl)
            .unwrap()
            .progress_chars("=> ")
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]);

        pb.set_style(style);

        if let Some(p) = prefix {
            pb.set_prefix(p.to_string());
        }

        if let Some(m) = message {
            pb.set_message(m.to_string());
        }

        // Sprint 4 (S4.3): hide on non-TTY stdout.
        maybe_hidden(pb)
    }

    pub fn print_stream_done(&self, r: &StreamResult) {
        println!(); // newline after progress bar
        println!("│  {:<16}: {}", "Blobs scanned", r.blobs_scanned);
        println!("│  {:<16}: {} KB", "Data processed", r.bytes_scanned / 1024);
        if r.files_saved > 0 || r.files_save_failed > 0 {
            println!(
                "│  {:<16}: {}  Failed: {}",
                "Files saved", r.files_saved, r.files_save_failed
            );
        }
        println!("│  {:<16}: {:.1}s", "Elapsed", r.elapsed_s);
        let source_total = r.object_source_stats.pack
            + r.object_source_stats.cache
            + r.object_source_stats.loose_http
            + r.object_source_stats.forge;
        if source_total > 0 {
            println!(
                "│  {:<16}: pack={} cache={} HTTP={} forge={}",
                "Object sources",
                r.object_source_stats.pack,
                r.object_source_stats.cache,
                r.object_source_stats.loose_http,
                r.object_source_stats.forge
            );
        }
        let skipped = r.outcome_stats.skipped_total();
        let failed = r.outcome_stats.failed_total();
        if skipped > 0 || failed > 0 {
            println!(
                "│  {:<16}: skipped={} failed={}",
                "Object outcomes", skipped, failed
            );
        }
        let archive_truncated = r.outcome_stats.truncated_total();
        if archive_truncated > 0 {
            println!(
                "│  {:<16}: {} bounded extraction events",
                "Archive limits", archive_truncated
            );
        }
        if r.outcome_stats.archive_invalid > 0 {
            println!(
                "│  {:<16}: {} malformed archive inputs",
                "Invalid archives", r.outcome_stats.archive_invalid
            );
        }
        if let Some(scope) = r.outcome_stats.scan_scope.as_deref() {
            println!("│  {:<16}: {}", "Scan scope", scope);
            if scope == "history" {
                println!(
                    "│  {:<16}: commits={} entries={} scanned={} dedup={} deleted={} truncated={}",
                    "History coverage",
                    r.outcome_stats.history_commits_scanned,
                    r.outcome_stats.history_entries_considered,
                    r.outcome_stats.history_entries_scanned,
                    r.outcome_stats.history_entries_deduplicated,
                    r.outcome_stats.history_deleted_entries,
                    r.outcome_stats.history_truncated
                );
            }
            if let Some(capability) = r.outcome_stats.unsupported_capability.as_deref() {
                println!("│  {:<16}: {}", "Unsupported", capability);
            }
        }
        // PERF-005: Display cache stats
        if r.cache_hits > 0 || r.cache_misses > 0 {
            let total_requests = r.cache_hits + r.cache_misses;
            let hit_rate = if total_requests > 0 {
                (r.cache_hits as f64 / total_requests as f64) * 100.0
            } else {
                0.0
            };
            println!(
                "│  {:<16}: {}/{} ({:.1}%)",
                "Cache hits", r.cache_hits, total_requests, hit_rate
            );
            if let Some(ref stats) = r.cache_stats {
                println!(
                    "│  {:<16}: {} entries, {}",
                    "Cache size", stats.total_entries, stats.size_human
                );
            }
        }
        println!("│");
    }

    /// Displays all deduplicated findings immediately after scanning, in card style.
    /// Shows a severity bar chart summary followed by individual finding cards.
    pub fn print_findings_summary(&self, findings: &[crate::streamer::Finding]) {
        let w = layout::calculate_box_width(60, layout::get_terminal_width());
        let sev_order = |s: &str| match s {
            "CRITICAL" => 0,
            "HIGH" => 1,
            "MEDIUM" => 2,
            "LOW" => 3,
            _ => 99,
        };

        let mut sorted = findings.to_vec();
        sorted.sort_by_key(|f| sev_order(&f.severity));

        let mut seen_keys = std::collections::HashSet::new();
        let deduped: Vec<_> = sorted
            .iter()
            .filter(|f| {
                let key = (
                    f.pattern_id.clone(),
                    f.match_str.chars().take(40).collect::<String>(),
                );
                seen_keys.insert(key)
            })
            .collect();

        let crit = deduped.iter().filter(|f| f.severity == "CRITICAL").count();
        let high = deduped.iter().filter(|f| f.severity == "HIGH").count();
        let med = deduped.iter().filter(|f| f.severity == "MEDIUM").count();
        let low = deduped.iter().filter(|f| f.severity == "LOW").count();
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
            println!(
                "│  {}  {:<8}  {:>3}  {}",
                "●".red().bold(),
                "CRITICAL".red().bold(),
                crit,
                make_bar(crit).red().bold()
            );
        }
        if high > 0 {
            println!(
                "│  {}  {:<8}  {:>3}  {}",
                "●".yellow().bold(),
                "HIGH".yellow().bold(),
                high,
                make_bar(high).yellow().bold()
            );
        }
        if med > 0 {
            println!(
                "│  {}  {:<8}  {:>3}  {}",
                "●".bright_yellow(),
                "MEDIUM".bright_yellow(),
                med,
                make_bar(med).bright_yellow()
            );
        }
        if low > 0 {
            println!(
                "│  {}  {:<8}  {:>3}  {}",
                "●".cyan(),
                "LOW".cyan(),
                low,
                make_bar(low).cyan()
            );
        }
        println!("│");

        // Individual finding cards (no cap — all findings shown)
        for (i, f) in deduped.iter().enumerate() {
            let sev_colored = ColorScheme::severity(&f.severity);
            let del_tag = if f.is_deleted {
                " · DELETED".dimmed().to_string()
            } else {
                String::new()
            };

            // Calculate right-side dashes: total line = 60 chars
            // "┌─[ #N · SEVERITY ]" + dashes + "┐"
            // prefix "┌─[" = 3, suffix "]" = 1, "┐" = 1 → fixed = 5 chars
            // header_plain used only for length, colored version in actual output
            let header_plain = format!(" #{} · {} ", i + 1, f.severity);
            let card_width = layout::calculate_box_width(60, layout::get_terminal_width());
            let right_dashes = (card_width - 5).saturating_sub(header_plain.len());
            println!(
                "\n┌─[ #{} · {} ]{}┐",
                (i + 1).to_string().bold(),
                sev_colored,
                "─".repeat(right_dashes)
            );
            println!("│  {:<12}: {}{}", "Type", f.description, del_tag);
            println!(
                "│  {:<12}: {}",
                "File",
                format!("{}  ·  line {}", f.filename, f.line).cyan()
            );
            let m = truncate_utf8(&f.match_str, 100);
            println!("│  {:<12}: {}", "Match", m);
            let ctx = truncate_utf8(&f.context, 120);
            println!("│  {:<12}: {}", "Context", ctx.dimmed());
            println!("└{}┘", "─".repeat(w));
        }
        println!();
    }

    /// Compact intelligence report footer shown after saving the report file.
    pub fn print_report(
        &self,
        _detect: &DetectResult,
        _map_r: &MapResult,
        stream_r: &StreamResult,
        report_path: &str,
    ) {
        let counts = stream_r.severity_counts();
        let (ai_total, _) = Self::ai_summary(&stream_r.findings);
        let risk = stream_r.risk_score();
        let risk_label = if risk >= 70 {
            "CRITICAL"
        } else if risk >= 40 {
            "HIGH"
        } else if risk >= 15 {
            "MEDIUM"
        } else {
            "CLEAR"
        };
        let risk_s = format!("{}/100  {}", risk, risk_label);
        let risk_colored = ColorScheme::risk(risk, &risk_s);

        let w = layout::calculate_box_width(60, layout::get_terminal_width());
        println!("\n╔{}╗", "═".repeat(w));
        println!("║  {:<width$}║", "INTELLIGENCE REPORT", width = w - 2);
        println!("╚{}╝", "═".repeat(w));
        println!("│  {:<14}: {}", "Risk Score", risk_colored);
        println!(
            "│  {:<14}: {}  [ {} {} {} ]",
            "Findings",
            stream_r.findings.len().to_string().bold(),
            format!("CRIT:{}", counts["CRITICAL"]).red().bold(),
            format!("HIGH:{}", counts["HIGH"]).yellow().bold(),
            format!("MED:{}", counts["MEDIUM"]).bright_yellow()
        );
        println!(
            "│  {:<14}: {}",
            "AI Findings",
            ai_total.to_string().magenta()
        );
        if !stream_r.tech_stack.is_empty() {
            println!(
                "│  {:<14}: {}",
                "Tech Stack",
                stream_r.tech_stack.join(", ")
            );
        }
        if !stream_r.contributors.is_empty() {
            println!(
                "│  {:<14}: {} found",
                "Developers",
                stream_r.contributors.len()
            );
        }
        println!(
            "│  {:<14}: {}  {}",
            "Report",
            report_path.green(),
            "✔".green().bold()
        );
        println!("│");
        println!("└{}┘\n", "─".repeat(w));
    }

    pub fn print_summary(&self, target: &str, stream_r: &StreamResult, report_path: &str) {
        let risk_s = format!("{}/100", stream_r.risk_score());
        let risk_colored = ColorScheme::risk(stream_r.risk_score(), &risk_s);
        let w = layout::calculate_box_width(60, layout::get_terminal_width());
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
            "version":   env!("CARGO_PKG_VERSION"),
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
                "object_sources":  s.object_source_stats,
                "outcomes":        s.outcome_stats,
                "findings":        s.findings.iter().map(|f| f.to_dict()).collect::<Vec<_>>(),
            });
        }

        let parent = Path::new(path).parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let json_str = serde_json::to_string_pretty(&report).map_err(std::io::Error::other)?;
        write_report_secure(path, json_str.as_bytes())
    }

    /// Save a JSON report for a `--token` scan.
    ///
    /// The report includes `"mode": "token"` at the top level so consumers can
    /// distinguish it from URL-based `.git` exposure reports.
    pub fn save_token_report(
        &self,
        path: &str,
        login: &str,
        repo_count: usize,
        stream_r: &StreamResult,
    ) -> std::io::Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let counts = stream_r.severity_counts();
        let (ai_total, ai_categories) = Self::ai_summary(&stream_r.findings);
        let report = serde_json::json!({
            "tool":       "GitRecon",
            "version":    env!("CARGO_PKG_VERSION"),
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
                "object_sources":  stream_r.object_source_stats,
                "outcomes":        stream_r.outcome_stats,
                "findings":        stream_r.findings.iter().map(|f| f.to_dict()).collect::<Vec<_>>(),
            }
        });
        let parent = Path::new(path).parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let json_str = serde_json::to_string_pretty(&report).map_err(std::io::Error::other)?;
        write_report_secure(path, json_str.as_bytes())
    }

    /// Print the final intelligence report for a `--token` scan to the terminal.
    pub fn print_token_report(
        &self,
        login: &str,
        repo_count: usize,
        stream_r: &StreamResult,
        report_path: &str,
    ) {
        let counts = stream_r.severity_counts();
        let (ai_total, _) = Self::ai_summary(&stream_r.findings);
        let risk = stream_r.risk_score();
        let risk_label = if risk >= 70 {
            "CRITICAL"
        } else if risk >= 40 {
            "HIGH"
        } else if risk >= 15 {
            "MEDIUM"
        } else {
            "CLEAR"
        };
        let risk_s = format!("{}/100  {}", risk, risk_label);
        let risk_colored = ColorScheme::risk(risk, &risk_s);

        let w = layout::calculate_box_width(60, layout::get_terminal_width());
        println!("\n╔{}╗", "═".repeat(w));
        println!("║  {:<width$}║", "TOKEN SCAN REPORT", width = w - 2);
        println!("╚{}╝", "═".repeat(w));
        println!("│  {:<14}: {}", "GitHub User", login.cyan().bold());
        println!("│  {:<14}: {}", "Repos Scanned", repo_count);
        println!("│  {:<14}: {}", "Risk Score", risk_colored);
        println!(
            "│  {:<14}: {}  [ {} {} {} ]",
            "Findings",
            stream_r.findings.len().to_string().bold(),
            format!("CRIT:{}", counts["CRITICAL"]).red().bold(),
            format!("HIGH:{}", counts["HIGH"]).yellow().bold(),
            format!("MED:{}", counts["MEDIUM"]).bright_yellow()
        );
        println!(
            "│  {:<14}: {}",
            "AI Findings",
            ai_total.to_string().magenta()
        );
        println!(
            "│  {:<14}: {} KB",
            "Data Processed",
            stream_r.bytes_scanned / 1024
        );
        println!("│  {:<14}: {:.1}s", "Elapsed", stream_r.elapsed_s);
        println!(
            "│  {:<14}: {}  {}",
            "Report",
            report_path.green(),
            "✔".green().bold()
        );
        println!("│");
        println!("└{}┘\n", "─".repeat(w));
    }

    // O-2: SARIF 2.1.0 output format
    //
    // Sprint 4 (S4.6) hardening:
    //   - Rules deduplicated by pattern_id (a scan with 1000 duplicates used to
    //     produce 1000 identical `rules` entries — file bloat plus some SARIF
    //     consumers rejected the run).
    //   - Driver populated with `informationUri` per SARIF spec §3.19.3.
    //   - Every rule carries `defaultConfiguration.level` matching the highest
    //     severity we observed for that pattern; consumers that surface rule
    //     configuration (GitHub code-scanning, Azure DevOps) render this correctly.
    pub fn save_sarif(
        &self,
        path: &str,
        _target: &str,
        stream_r: Option<&StreamResult>,
    ) -> std::io::Result<()> {
        // pattern_id -> (level, description) so we emit each rule once.
        let mut rules_by_id: HashMap<String, (&'static str, String)> = HashMap::new();
        let mut results = Vec::new();

        // Rank severities so we can keep the strictest level per rule.
        let rank = |lvl: &str| -> u8 {
            match lvl {
                "error" => 3,
                "warning" => 2,
                "note" => 1,
                _ => 0,
            }
        };

        if let Some(s) = stream_r {
            for f in &s.findings {
                let level: &'static str = match f.severity.as_str() {
                    "CRITICAL" | "HIGH" => "error",
                    "MEDIUM" => "warning",
                    _ => "note",
                };

                // Upsert the rule, keeping the highest-severity level and the first
                // non-empty description we see for this pattern_id.
                rules_by_id
                    .entry(f.pattern_id.clone())
                    .and_modify(|(existing_level, _)| {
                        if rank(level) > rank(existing_level) {
                            *existing_level = level;
                        }
                    })
                    .or_insert_with(|| (level, f.description.clone()));

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

        // Emit rules in deterministic order so diffs across runs stay stable.
        let mut rule_ids: Vec<&String> = rules_by_id.keys().collect();
        rule_ids.sort();
        let rules: Vec<serde_json::Value> = rule_ids
            .into_iter()
            .map(|id| {
                let (level, desc) = &rules_by_id[id];
                serde_json::json!({
                    "id": id,
                    "name": id,
                    "shortDescription": {"text": desc},
                    "defaultConfiguration": {"level": level},
                })
            })
            .collect();

        let sarif = serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "GitRecon",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/HazaVVIP/GitRecon",
                        "rules": rules,
                    }
                },
                "results": results
            }]
        });

        let parent = Path::new(path).parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let json_str = serde_json::to_string_pretty(&sarif).map_err(std::io::Error::other)?;
        write_report_secure(path, json_str.as_bytes())
    }

    // O-3: CSV output format
    pub fn save_csv(&self, path: &str, stream_r: Option<&StreamResult>) -> std::io::Result<()> {
        let parent = Path::new(path).parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        // CSV schema:
        // file,line,severity,type,description,match,deleted,ai_related,ai_category,ai_tags
        let mut out = String::from(
            "file,line,severity,type,description,match,deleted,ai_related,ai_category,ai_tags\n",
        );
        if let Some(s) = stream_r {
            for f in &s.findings {
                let (ai_related, ai_category, ai_tags) =
                    crate::streamer::ai_metadata_for_finding(f);
                // Sprint 2 (S2.3): every field wrapped in double quotes uniformly, internal
                // `"` escaped as `""` per RFC 4180. Previously `filename` and `pattern_id`
                // were unquoted, so a legal comma or double-quote in a filename shifted
                // every downstream column.
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{}\n",
                    csv_field(&f.filename),
                    f.line,
                    csv_field(&f.severity),
                    csv_field(&f.pattern_id),
                    csv_field(&f.description),
                    csv_field(&f.match_str),
                    f.is_deleted,
                    ai_related,
                    csv_field(&ai_category.unwrap_or_default()),
                    csv_field(&ai_tags.join("|")),
                ));
            }
        }
        write_report_secure(path, out.as_bytes())
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
        write_report_secure(path, out.as_bytes())
    }

    // O-3: Markdown output format
    pub fn save_markdown(
        &self,
        path: &str,
        target: &str,
        stream_r: Option<&StreamResult>,
    ) -> std::io::Result<()> {
        let parent = Path::new(path).parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        // Sprint 2 (S2.2): target is attacker-controlled (repo URL). Escape it before
        // interpolating into the H1 line so a `[label](evil://x)` in the URL doesn't
        // turn into a live link.
        let mut out = format!(
            "# GitRecon Report\n\n**Target:** {}\n\n",
            md_cell_escape(target)
        );
        out.push_str("| Severity | Type | File | Line | AI | Match |\n");
        out.push_str("|----------|------|------|------|----|-------|\n");
        if let Some(s) = stream_r {
            for f in &s.findings {
                let emoji = match f.severity.as_str() {
                    "CRITICAL" => "🔴",
                    "HIGH" => "🟡",
                    "MEDIUM" => "🟠",
                    "LOW" => "🔵",
                    _ => "⚪",
                };
                let m = truncate_utf8(&f.match_str, 60);
                let (ai_related, ai_category, _) = crate::streamer::ai_metadata_for_finding(f);
                let ai_col = if ai_related {
                    format!("✅ {}", ai_category.unwrap_or_else(|| "ai".to_string()))
                } else {
                    "—".to_string()
                };
                // Every cell escaped: `|` breaks the table, backticks close our inline-code
                // wrapper, `[..](..)` becomes a clickable link that could exfiltrate the
                // reviewer's credentials via a crafted repo filename or secret payload.
                out.push_str(&format!(
                    "| {} {} | {} | {} | {} | {} | `{}` |\n",
                    emoji,
                    md_cell_escape(&f.severity),
                    md_cell_escape(&f.pattern_id),
                    md_cell_escape(&f.filename),
                    f.line,
                    md_cell_escape(&ai_col),
                    md_cell_escape(m),
                ));
            }
        }
        write_report_secure(path, out.as_bytes())
    }

    // O-3: HTML output format
    pub fn save_html(
        &self,
        path: &str,
        target: &str,
        stream_r: Option<&StreamResult>,
    ) -> std::io::Result<()> {
        let parent = Path::new(path).parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let mut rows = String::new();
        if let Some(s) = stream_r {
            for f in &s.findings {
                // Severity → CSS color chosen from a fixed allowlist. `f.severity` is checked
                // against known values only — the color itself never contains user input.
                let color = match f.severity.as_str() {
                    "CRITICAL" => "#ff4444",
                    "HIGH" => "#ff8800",
                    "MEDIUM" => "#ffbb00",
                    "LOW" => "#4488ff",
                    _ => "#888888",
                };
                let m = truncate_utf8(&f.match_str, 80);
                let (ai_related, ai_category, _) = crate::streamer::ai_metadata_for_finding(f);
                let ai_col = if ai_related {
                    ai_category.unwrap_or_else(|| "ai".to_string())
                } else {
                    "no".to_string()
                };
                // Sprint 2 (S2.1): every attacker-controlled field routed through html_escape
                // before landing between tags. Previously `filename` and `match_str` reached
                // the DOM raw — a filename like `<img src=x onerror=fetch(...)>` inside a
                // scanned repo would fire when the reviewer opened the report.
                rows.push_str(&format!(
                    "<tr><td style='color:{}'>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>\n",
                    color,
                    html_escape(&f.severity),
                    html_escape(&f.pattern_id),
                    html_escape(&f.filename),
                    f.line,
                    html_escape(&ai_col),
                    html_escape(m),
                ));
            }
        }
        let html = format!(
            r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>GitRecon Report</title>
<style>body{{font-family:sans-serif;margin:2em}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:8px;text-align:left}}th{{background:#222;color:#fff}}</style>
</head><body>
<h1>GitRecon Report</h1>
<p><strong>Target:</strong> {}</p>
<table><thead><tr><th>Severity</th><th>Type</th><th>File</th><th>Line</th><th>AI</th><th>Match</th></tr></thead>
<tbody>{}</tbody></table>
</body></html>"#,
            html_escape(target),
            rows
        );
        write_report_secure(path, html.as_bytes())
    }

    // O-4: Webhook integration
    fn compute_hmac_sha256(key: &str, data: &str) -> Result<String, anyhow::Error> {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(key.as_bytes())
            .map_err(|_| anyhow::anyhow!("HMAC key must be at least 1 byte"))?;
        mac.update(data.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
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
            if let Ok(sig) = Self::compute_hmac_sha256(key, body) {
                extra_headers.push(("X-GitRecon-Signature".to_string(), sig));
            }
            // If HMAC fails, we proceed without signature
        }
        let resp = client.post(url, body, &extra_headers).await;
        resp.status >= 200 && resp.status < 300
    }

    // Theme-aware helper methods

    /// Get unicode symbol based on theme settings
    pub fn unicode_symbol(&self, unicode: &str, ascii: &str) -> String {
        if self.theme.unicode {
            unicode.to_string()
        } else {
            ascii.to_string()
        }
    }

    /// Get check mark symbol based on theme settings
    pub fn check_mark(&self) -> String {
        self.unicode_symbol("✔", "OK")
    }

    /// Get warning symbol based on theme settings
    pub fn warning_symbol(&self) -> String {
        self.unicode_symbol("⚠", "!")
    }

    /// Get cross mark symbol based on theme settings
    pub fn cross_mark(&self) -> String {
        self.unicode_symbol("✘", "X")
    }

    /// Get arrow symbol based on theme settings
    pub fn arrow_symbol(&self) -> String {
        self.unicode_symbol("▶", "->")
    }

    /// Get bullet symbol based on theme settings
    pub fn bullet_symbol(&self) -> String {
        self.unicode_symbol("●", "*")
    }

    /// Apply theme color scheme for severity
    pub fn theme_severity(&self, severity: &str) -> colored::ColoredString {
        let color = match severity {
            "CRITICAL" => &self.theme.colors.critical,
            "HIGH" => &self.theme.colors.high,
            "MEDIUM" => &self.theme.colors.medium,
            "LOW" => &self.theme.colors.low,
            _ => &self.theme.colors.info,
        };
        match color.as_str() {
            "red" => severity.red(),
            "yellow" => severity.yellow(),
            "green" => severity.green(),
            "blue" => severity.blue(),
            "cyan" => severity.cyan(),
            "white" => severity.white(),
            _ => severity.normal(),
        }
    }

    /// Apply theme color scheme for success messages
    pub fn theme_success(&self, text: &str) -> colored::ColoredString {
        match self.theme.colors.success.as_str() {
            "red" => text.red(),
            "yellow" => text.yellow(),
            "green" => text.green(),
            "blue" => text.blue(),
            "cyan" => text.cyan(),
            "white" => text.white(),
            _ => text.normal(),
        }
    }

    /// Apply theme color scheme for info messages
    pub fn theme_info(&self, text: &str) -> colored::ColoredString {
        match self.theme.colors.info.as_str() {
            "red" => text.red(),
            "yellow" => text.yellow(),
            "green" => text.green(),
            "blue" => text.blue(),
            "cyan" => text.cyan(),
            "white" => text.white(),
            _ => text.normal(),
        }
    }

    /// Check if compact mode is enabled in theme
    pub fn is_compact(&self) -> bool {
        self.theme.compact
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

    #[test]
    fn save_aggregate_report_preserves_schema() {
        let path = std::env::temp_dir().join(format!(
            "gitrecon-aggregate-report-{}.json",
            std::process::id()
        ));
        let summary = crate::outcome::ScanSummary {
            report_path: "out/target_report.json".to_string(),
            findings_count: 2,
            risk_score: 7,
        };
        let outcome = TargetOutcome::success("target", "URL", &summary);
        save_aggregate_report(path.to_str().unwrap(), 3, &[outcome])
            .expect("aggregate report should be written");
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["tool"], "GitRecon");
        assert_eq!(value["total_targets"], 3);
        assert_eq!(value["scanned_targets"], 1);
        assert_eq!(value["results"][0]["findings_count"], 2);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn build_report_path_preserves_format_contract() {
        assert_eq!(
            build_report_path("out", "target", "sarif"),
            "out/target_report.sarif"
        );
        assert_eq!(
            build_report_path("out", "target", "html"),
            "out/target_report.html"
        );
        assert_eq!(
            build_report_path("out", "target", "unknown"),
            "out/target_report.json"
        );
    }

    fn unicode_finding() -> Finding {
        Finding {
            filename: "/tmp/demo.rs".to_string(),
            line: 42,
            pattern_id: "jwt_secret".to_string(),
            description: "JWT Secret".to_string(),
            severity: "CRITICAL".to_string(),
            match_str: "secret🔐─你好🌍".repeat(16),
            context: "const ECOMM_JWT_SECRET = process.env.ECOMM_JWT_SECRET || \"密钥─🔒\""
                .repeat(8),
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
            object_source_stats: crate::streamer::ObjectSourceStats::default(),
            outcome_stats: crate::streamer::ScanOutcomeStats::default(),
        }
    }

    #[test]
    fn print_findings_summary_handles_unicode_without_panic() {
        let rep = Reporter::new(true, &ui::theme::Theme::default());
        let findings = vec![unicode_finding()];
        rep.print_findings_summary(&findings);
    }

    #[test]
    fn save_json_includes_stream_metrics() {
        let rep = Reporter::new(true, &ui::theme::Theme::default());
        let stream = unicode_stream_result();
        let path = std::env::temp_dir().join(format!(
            "gitrecon_metrics_report_{}.json",
            std::process::id()
        ));
        let path_str = path.to_string_lossy().to_string();

        rep.save_json(&path_str, "target", None, None, Some(&stream))
            .expect("save JSON report");
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["result"]["object_sources"]["pack"], 0);
        assert!(value["result"]["outcomes"].is_object());
        assert!(value["result"]["outcomes"]["failed_http_statuses"].is_object());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn save_markdown_and_html_handle_unicode_without_panic() {
        let rep = Reporter::new(true, &ui::theme::Theme::default());
        let stream = unicode_stream_result();
        let tmp =
            std::env::temp_dir().join(format!("gitrecon_reporter_test_{}", std::process::id()));
        let _guard = TempDirGuard::new(tmp.clone());

        let md_path = tmp.join("report.md");
        let html_path = tmp.join("report.html");
        let md_str = md_path.to_string_lossy().to_string();
        let html_str = html_path.to_string_lossy().to_string();

        rep.save_markdown(&md_str, "target", Some(&stream))
            .expect("save markdown");
        rep.save_html(&html_str, "target", Some(&stream))
            .expect("save html");
    }

    // ── Sprint 2 — output escaping ───────────────────────────────────────────

    #[test]
    fn html_escape_covers_five_dangerous_chars() {
        assert_eq!(html_escape("<img>"), "&lt;img&gt;");
        assert_eq!(html_escape("a\"b"), "a&quot;b");
        assert_eq!(html_escape("a'b"), "a&#39;b");
        assert_eq!(html_escape("a&b"), "a&amp;b");
    }

    #[test]
    fn html_escape_neutralises_script_injection_from_filename() {
        let attacker = "<script>alert(1)</script>.txt";
        let escaped = html_escape(attacker);
        assert!(
            !escaped.contains("<script"),
            "raw <script must not survive: {escaped}"
        );
        assert!(escaped.starts_with("&lt;script"));
    }

    #[test]
    fn md_cell_escape_defangs_pipe_and_link_syntax() {
        let out = md_cell_escape("a|b [x](y) `code` \\path");
        assert!(out.contains("\\|"));
        assert!(out.contains("\\["));
        assert!(out.contains("\\]"));
        assert!(out.contains("\\`"));
        assert!(out.contains("\\\\"));
    }

    #[test]
    fn md_cell_escape_collapses_newlines() {
        let out = md_cell_escape("first\nsecond\r\nthird");
        assert!(!out.contains('\n'));
        assert!(!out.contains('\r'));
    }

    #[test]
    fn csv_field_always_wraps_in_double_quotes() {
        assert!(csv_field("plain").starts_with('"'));
        assert!(csv_field("plain").ends_with('"'));
    }

    #[test]
    fn csv_field_doubles_internal_quotes() {
        let out = csv_field("a\"b");
        assert_eq!(out, "\"a\"\"b\"");
    }

    #[test]
    fn csv_field_neutralises_formula_injection() {
        // sanitize_csv_field prepends `'` to `=`/`+`/`-`/`@` — csv_field then wraps.
        let out = csv_field("=CMD");
        assert!(
            out.starts_with("\"'") || out.starts_with("\"\\'"),
            "expected leading quote-prefix on formula, got {out}"
        );
    }

    #[test]
    fn html_report_body_has_no_raw_script_tag() {
        let rep = Reporter::new(true, &ui::theme::Theme::default());
        let attack = Finding {
            filename: "<script>alert(1)</script>.txt".into(),
            line: 1,
            pattern_id: "<img src=x onerror=alert(1)>".into(),
            description: "test".into(),
            severity: "HIGH".into(),
            match_str: "</code><script>alert(2)</script>".into(),
            context: String::new(),
            is_deleted: false,
            commit_sha1: None,
            confidence_adjustment: None,
        };
        let mut sr = StreamResult::default();
        sr.findings.push(attack);
        let tmp = std::env::temp_dir().join(format!("gitrecon_xss_test_{}", std::process::id()));
        let _guard = TempDirGuard::new(tmp.clone());
        let html_path = tmp.join("report.html");
        rep.save_html(
            &html_path.to_string_lossy(),
            "https://evil.example/<img onerror=x>",
            Some(&sr),
        )
        .expect("write");
        let body = std::fs::read_to_string(&html_path).expect("read");
        // Only expected <script> tags are ours (there are none in the template).
        assert!(
            !body.contains("<script"),
            "attacker <script tag leaked into HTML report"
        );
        assert!(
            !body.contains("onerror="),
            "attacker onerror attribute leaked into HTML report"
        );
    }

    // ── Sprint 4 (S4.6) — SARIF rule dedup & spec compliance ─────────────────

    fn make_finding(pattern_id: &str, severity: &str) -> Finding {
        Finding {
            filename: "a.txt".into(),
            line: 1,
            pattern_id: pattern_id.into(),
            description: format!("desc for {}", pattern_id),
            severity: severity.into(),
            match_str: "REDACTED".into(),
            context: String::new(),
            is_deleted: false,
            commit_sha1: None,
            confidence_adjustment: None,
        }
    }

    fn write_sarif(findings: Vec<Finding>) -> serde_json::Value {
        let rep = Reporter::new(true, &ui::theme::Theme::default());
        let sr = StreamResult {
            findings,
            ..Default::default()
        };
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        let tmp = std::env::temp_dir().join(format!(
            "gitrecon_sarif_test_{}_{}",
            std::process::id(),
            nonce
        ));
        let _guard = TempDirGuard::new(tmp.clone());
        std::fs::create_dir_all(&tmp).expect("create SARIF test directory");
        let sarif_path = tmp.join("out.sarif");
        rep.save_sarif(&sarif_path.to_string_lossy(), "target", Some(&sr))
            .expect("write");
        let body = std::fs::read_to_string(&sarif_path).expect("read");
        serde_json::from_str(&body).expect("parse")
    }

    #[test]
    fn sarif_dedupes_rules_by_pattern_id() {
        // 3 findings of the same pattern must produce 1 rule but 3 results.
        let findings = vec![
            make_finding("aws_key", "HIGH"),
            make_finding("aws_key", "HIGH"),
            make_finding("aws_key", "HIGH"),
        ];
        let sarif = write_sarif(findings);
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(rules.len(), 1, "duplicate rules must be deduped");
        assert_eq!(results.len(), 3, "results must NOT be deduped");
    }

    #[test]
    fn sarif_rule_keeps_strictest_severity_across_finds() {
        // Same pattern seen at LOW then CRITICAL → rule's defaultConfiguration.level
        // must be "error" (the stricter one).
        let findings = vec![
            make_finding("mixed", "LOW"),
            make_finding("mixed", "CRITICAL"),
        ];
        let sarif = write_sarif(findings);
        let rule = &sarif["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(
            rule["defaultConfiguration"]["level"].as_str().unwrap(),
            "error"
        );
    }

    #[test]
    fn sarif_driver_includes_information_uri_and_version() {
        let sarif = write_sarif(vec![]);
        let driver = &sarif["runs"][0]["tool"]["driver"];
        assert!(
            driver["informationUri"].as_str().is_some(),
            "SARIF spec §3.19.3 informationUri missing"
        );
        // Version should be the CARGO_PKG_VERSION, not the hardcoded literal.
        let version = driver["version"].as_str().unwrap();
        assert_eq!(
            version,
            env!("CARGO_PKG_VERSION"),
            "driver.version must match Cargo.toml"
        );
    }
}
