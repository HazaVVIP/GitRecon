# GitRecon CLI Design Audit Report

> **Focus**: Code Quality & CLI Design  
> **Date**: 2026-07-11  
> **Version**: 3.2.4

---

## Executive Summary

### Key Findings

1. **🎨 Logo terlalu besar** - 6 baris ASCII art menghabiskan screen space berharga
2. **📐 Hardcoded terminal width** - Box output fixed 58 chars, tidak responsive
3. **🔄 Progress bar sederhana** - Tidak ada ETA, throughput, atau multi-stage support
4. **🏗️ Code organization** - main.rs 4172 baris, CLI logic tersebar
5. **🎯 Missing features** - Theme system, mini banner, responsive layout

### Priority Recommendations (Impact/Effort)

| Priority | Recommendation | Impact | Effort |
|----------|----------------|--------|--------|
| P0 | Mini banner with --compact flag | High | Low |
| P1 | Responsive terminal width | High | Medium |
| P1 | Enhanced progress with ETA | Medium | Medium |
| P2 | Extract UI module structure | High | High |
| P3 | Theme system | Medium | High |

---

## Current State Analysis

### 1. Logo/Banner (reporter.rs:47-60)

```rust
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
```

**Issues:**
- 6 baris vertikal space
- 53 karakter lebar (banyak space terbuang di kanan untuk narrow terminals)
- Tidak ada opsi untuk tampilan compact
- Full block ASCII terasa "dated" untuk modern CLI aesthetic

### 2. Progress Bar (reporter.rs:123-137)

```rust
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
```

**Strengths:**
- Clean design dengan ▶ arrow prefix
- Color-coded findings counter
- Good character choice (█/░)

**Missing:**
- ETA / time remaining
- Throughput (objs/sec, MB/sec)
- Multi-stage progress untuk pipeline operations
- Spinners untuk indeterminate operations

### 3. Color Scheme (reporter.rs:453-478)

```rust
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
```

**Analysis:**
- Semantic color mapping (good)
- High vs bright_yellow bisa susah dibedakan
- Tidak konsisten: severity pakai bold untuk CRITICAL saja, confidence pakai bold untuk CONFIRMED saja

### 4. Output Boxes (reporter.rs:72-88, 93-111, etc.)

```rust
pub fn print_detect(&self, r: &DetectResult) {
    let w = 58usize;
    println!("\n╔{}╗", "═".repeat(w));
    println!("║  {:<width$}║", "DETECTION", width = w - 2);
    println!("╚{}╝", "═".repeat(w));
    println!("│  {:<14}: {}", "Target", r.url);
    // ...
}
```

**Issues:**
- Hardcoded width = 58 chars
- Tidak responsive terhadap terminal size
- Box drawing characters konsisten (good)

### 5. Code Organization

```
main.rs (4172 lines):
├── Modules: 21 imports
├── CLI struct: 90-334 (~244 lines)
├── Helpers: 340-531 (~191 lines)
├── Token scan pipelines: 578-2408 (~1830 lines!)
│   ├── run_token_scan: ~430 lines
│   ├── run_gitlab_token_scan: ~440 lines
│   ├── run_bitbucket_token_scan: ~440 lines
│   ├── run_gitea_token_scan: ~440 lines
│   └── run_azure_token_scan: ~?? lines
├── URL scan pipeline: ~300 lines
└── Run function: ~200 lines

reporter.rs (758 lines):
├── Banner: ~14 lines
├── Detection print: ~27 lines
├── Map print: ~21 lines
├── Progress bar: ~15 lines
├── Findings summary: ~88 lines
├── Report prints: ~30 lines
├── Save functions: ~150 lines
└── Tests: ~80 lines
```

**Issues:**
- main.rs terlalu besar (4K+ lines)
- Business logic dan presentation logic tercampur
- Duplikasi di token scan pipelines

---

## Recommendations

### P0: Mini Banner

**Rationale:** Screen real estate berharga, modern CLI tools gunakan compact banners.

**Implementation:**

```rust
// reporter.rs
pub enum BannerStyle {
    Full,
    Mini,
    None,
}

impl Reporter {
    pub fn banner_with_style(&self, style: BannerStyle) {
        match style {
            BannerStyle::Full => self.banner_full(),
            BannerStyle::Mini => self.banner_mini(),
            BannerStyle::None => {},
        }
    }

    fn banner_full(&self) {
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
        println!();
    }

    fn banner_mini(&self) {
        // Option 1: Minimal text
        println!("{} {}", "▌".cyan(), "gitrecon".cyan().bold());
        println!("  {} {}", "v3.2".dimmed(), "Git Exposure Scanner".dimmed());
        println!();

        // Option 2: Even more minimal
        // println!("{} {} v{}", "▌".cyan(), "gitrecon".cyan().bold(), "3.2".dimmed());
        // println!();
    }
}

// main.rs - add flag
#[arg(long = "compact", help = "Use compact output (mini banner, condensed boxes)")]
compact: bool,

// usage:
let banner_style = if args.compact {
    BannerStyle::Mini
} else if args.quiet || args.pipe {
    BannerStyle::None
} else {
    BannerStyle::Full
};
rep.banner_with_style(banner_style);
```

### P1: Responsive Terminal Width

**Rationale:** Fixed width breaks di narrow/wide terminals.

**Implementation:**

```rust
// Cargo.toml - add dependency
// terminal_size = "0.4"

// src/ui/layout.rs
use terminal_size::{Width, Height, terminal_size};

pub fn get_terminal_width() -> usize {
    terminal_size()
        .map(|(Width(w), Height(_h))| w as usize)
        .unwrap_or(80) // fallback
}

pub fn calculate_box_width(min: usize, max: usize) -> usize {
    get_terminal_width()
        .min(max)
        .max(min)
}

// reporter.rs
impl Reporter {
    pub fn print_detect(&self, r: &DetectResult) {
        let w = calculate_box_width(60, 100);
        // rest same with dynamic w
    }
}
```

### P1: Enhanced Progress Bar

**Rationale:** Users want ETA dan throughput metrics.

```rust
// reporter.rs - using indicatif
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

impl Reporter {
    pub fn create_progress(&self, total: usize, msg: &str) -> ProgressBar {
        let pb = ProgressBar::new(total as u64);
        pb.set_message(msg);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {eta} 
                    ({per_sec}, {bytes})")
                .progress_chars("█░")
                .elapsed_chars("▸")
        );
        pb
    }

    pub fn create_multi_stage() -> MultiProgress {
        let mp = MultiProgress::new();
        
        let main = mp.add(ProgressBar::new(total));
        main.set_style(ProgressStyle::default_bar()
            .template("[{bar:40}] {pos}/{len}")
            .progress_chars("█░"));
        
        let detail = mp.add(ProgressBar::new_spinner());
        detail.set_style(ProgressStyle::default_spinner()
            .template("{spinner} {msg}"));
        
        mp
    }
}
```

### P2: Extract UI Module

**Rationale:** Better separation of concerns, reusability.

**Proposed Structure:**

```
src/
├── ui/
│   ├── mod.rs
│   ├── banner.rs      // Banner logic
│   ├── progress.rs    // Progress bars, spinners
│   ├── boxes.rs       // Box drawing, tables
│   ├── colors.rs      // Color utilities
│   ├── theme.rs       // Theme configuration
│   └── layout.rs      // Terminal size, responsive layout
├── main.rs            // Entry point, delegation
├── reporter.rs        // Report generation (delegates to ui/)
└── [other modules]
```

**Module Example:**

```rust
// src/ui/mod.rs
pub mod banner;
pub mod progress;
pub mod boxes;
pub mod colors;
pub mod theme;
pub mod layout;

pub use banner::{Banner, BannerStyle};
pub use progress::{Progress, MultiStage};
pub use boxes::{Box, Table, Card};
pub use colors::{ColorScheme, SeverityColor};
pub use theme::Theme;

// src/ui/banner.rs
pub struct Banner {
    style: BannerStyle,
}

impl Banner {
    pub fn new(style: BannerStyle) -> Self {
        Self { style }
    }

    pub fn print(&self) {
        match self.style {
            BannerStyle::Full => Self::print_full(),
            BannerStyle::Mini => Self::print_mini(),
            BannerStyle::None => {},
        }
    }

    fn print_full() {
        // full banner logic
    }

    fn print_mini() {
        println!("{} {}", "▌".cyan(), "gitrecon".cyan().bold());
        println!("  {} v{}", "Git Exposure Scanner".dimmed(), env!("CARGO_PKG_VERSION").dimmed());
        println!();
    }
}

// src/ui/colors.rs
use colored::*;

pub struct ColorScheme {
    pub critical: Color,
    pub high: Color,
    pub medium: Color,
    pub low: Color,
    pub info: Color,
    pub success: Color,
}

impl Default for ColorScheme {
    fn default() -> Self {
        Self {
            critical: Color::Red,
            high: Color::Yellow,
            medium: Color::BrightYellow,
            low: Color::Cyan,
            info: Color::Blue,
            success: Color::Green,
        }
    }
}

impl ColorScheme {
    pub fn severity(&self, sev: &str) -> ColoredString {
        match sev {
            "CRITICAL" => sev.color(self.critical).bold(),
            "HIGH" => sev.color(self.high),
            "MEDIUM" => sev.color(self.medium),
            "LOW" => sev.color(self.low),
            _ => sev.normal(),
        }
    }
}

// src/ui/boxes.rs
use crate::ui::layout::calculate_box_width;

pub struct Box {
    width: usize,
}

impl Box {
    pub fn new() -> Self {
        Self {
            width: calculate_box_width(60, 100),
        }
    }

    pub fn print_header(&self, title: &str) {
        let w = self.width;
        println!("\n╔{}╗", "═".repeat(w - 2));
        println!("║  {:<width$}║", title, width = w - 4);
        println!("╚{}╝", "═".repeat(w - 2));
    }

    pub fn print_row(&self, key: &str, value: &str) {
        println!("│  {:<16}: {}", key, value);
    }
}
```

### P3: Theme System

**Rationale:** User customization, consistency across output.

```rust
// src/ui/theme.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Theme {
    pub banner_style: BannerStyle,
    pub colors: ColorScheme,
    pub compact: bool,
    pub unicode: bool,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            banner_style: BannerStyle::Full,
            colors: ColorScheme::default(),
            compact: false,
            unicode: true,
        }
    }
}

// Load from ~/.gitrecon/theme.toml or --theme flag
impl Theme {
    pub fn load() -> Result<Self> {
        let config_path = dirs::config_dir()
            .ok_or_else(|| anyhow!("no config dir"))?
            .join("gitrecon/theme.toml");
        
        if config_path.exists() {
            let content = std::fs::read_to_string(config_path)?;
            toml::from_str(&content).map_err(Into::into)
        } else {
            Ok(Self::default())
        }
    }
}
```

---

## Implementation Roadmap

### Phase 1: Quick Wins (1-2 days)

1. **Mini banner** + `--compact` flag
2. **Refactor color functions** untuk consistency
3. **Add `--no-banner` flag**

### Phase 2: Responsive Layout (2-3 days)

1. Add `terminal_size` dependency
2. Extract layout utilities to `src/ui/layout.rs`
3. Update all box drawing untuk gunakan dynamic width
4. Test di various terminal sizes

### Phase 3: Enhanced Progress (3-4 days)

1. Integrate `indicatif` lebih fully
2. Add multi-stage progress
3. Add ETA dan throughput
4. Progress persistence untuk resume capability

### Phase 4: UI Module Extraction (1 week)

1. Create `src/ui/` module structure
2. Migrate banner code
3. Migrate progress code
4. Migrate boxes/color code
5. Update main.rs dan reporter.rs untuk delegate ke ui/

### Phase 5: Theme System (optional, 1 week)

1. Design theme TOML schema
2. Implement theme loading
3. Add `--theme` flag
4. Document theme customization

---

## Code Examples

### Example 1: Compact Output

```rust
// Before
╔════════════════════════════════════════╗
║  DETECTION                              ║
╚════════════════════════════════════════╝
│  Target        : https://example.com
│  Git URL       : https://example.com/.git
│  Confidence    : CONFIRMED (85%)  ✔
│  Dir List      : OFF
│  Server        : Apache/2.4.41

// After (compact)
▶ Detection: https://example.com
  │ Git: https://example.com/.git
  │ Conf: 85% CONFIRMED
  │ Server: Apache/2.4.41
```

### Example 2: Multi-Stage Progress

```rust
Scanning repos     [████████████░░░░░░░] 60% (12/20) ETA: 2m30s
├─ Fetching tree  [██████████████████] 100% (2/2)
├─ Downloading     [█████░░░░░░░░░░░░░] 25% (150/600)
└─ Scanning        [░░░░░░░░░░░░░░░░░░░] 0% (0/600)
```

### Example 3: Responsive Box

```rust
// 80-char terminal
╔══════════════════════════════════════════════════════════════════════════════╗
║  FINDINGS                                                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

// 40-char terminal (rare, but should work)
╔════════════════════════════════════╗
║  FINDINGS                           ║
╚════════════════════════════════════╝
```

---

## Testing Strategy

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_banner_mini_fits_in_40_chars() {
        let output = capture_output(|| Banner::mini().print());
        assert!(output.lines().all(|l| l.len() <= 40));
    }

    #[test]
    fn test_progress_bar_format() {
        let pb = Progress::new(100);
        pb.tick(50);
        let output = pb.to_string();
        assert!(output.contains("50%"));
    }

    #[test]
    fn test_box_width_responsive() {
        mock_terminal_width(80, || {
            let box = Box::new();
            assert_eq!(box.width(), 80);
        });
    }
}
```

---

## References

### Modern CLI Tools for Inspiration

| Tool | URL | Notable Feature |
|------|-----|----------------|
| ripgrep | https://github.com/BurntSushi/ripgrep | Minimal output, colors |
| fd | https://github.com/sharkdp/fd | Compact, beautiful output |
| bat | https://github.com/sharkdp/bat | Syntax highlighting, git integration |
| delta | https://github.com/dandavison/delta | Beautiful diff viewer |
| exa | https://github.com/ogham/exa | Modern ls replacement |
| dust | https://github.com/bootandy/dust | Intuitive du replacement |
| gdu | https://github.com/dundee/gdu | Disk usage analyzer |

### Design Principles

1. **Default to concise output** - verbose opt-in
2. **Respect user's screen** - responsive, don't overflow
3. **Color semantics** - red=bad, green=good, yellow=warning
4. **Progress feedback** - show what's happening, especially for long ops
5. **Quiet modes** - `--quiet`, `--silent` for scripting

---

## Conclusion

GitRecon sudah memiliki dasar CLI design yang baik dengan colors dan boxes. Key improvements:

1. **Immediate**: Add mini banner dengan `--compact` flag
2. **Short-term**: Responsive terminal width
3. **Medium-term**: Enhanced progress dengan ETA
4. **Long-term**: UI module extraction untuk maintainability

Ini akan membuat GitRecon lebih modern, user-friendly, dan professional sebagai bagian dari Fable5 ecosystem.
