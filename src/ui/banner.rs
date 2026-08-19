//! # Banner Component
//!
//! ASCII art banner display for gitrecon branding and version information.
//!
//! Provides multiple banner styles for different display modes:
//! - Full: 3-line banner with horizontal line, diamond, and version
//! - Mini: Compact single-line banner
//! - None: No banner output

use colored::*;
use std::fmt;

/// Banner display style
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BannerStyle {
    /// Full 3-line banner with horizontal line, diamond, and version
    Full,
    /// Compact single-line banner
    Mini,
    /// No banner output
    None,
}

/// ASCII art banner for gitrecon
#[derive(Debug, Clone)]
pub struct Banner {
    /// Show version information
    pub show_version: bool,
    /// Custom title text
    pub title: Option<String>,
    /// Enable colored output
    pub colored: bool,
    /// Banner style to use
    pub style: BannerStyle,
}

impl Default for Banner {
    fn default() -> Self {
        Self {
            show_version: true,
            title: None,
            colored: true,
            style: BannerStyle::Full,
        }
    }
}

impl Banner {
    /// Create a new Banner with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new Banner with custom title
    #[allow(dead_code)]
    pub fn with_title(title: impl Into<String>) -> Self {
        Self {
            title: Some(title.into()),
            ..Default::default()
        }
    }

    /// Set whether to show version information
    #[allow(dead_code)]
    pub fn show_version(mut self, show: bool) -> Self {
        self.show_version = show;
        self
    }

    /// Set whether to use colored output
    #[allow(dead_code)]
    pub fn colored(mut self, colored: bool) -> Self {
        self.colored = colored;
        self
    }

    /// Set the banner style
    #[allow(dead_code)]
    pub fn style(mut self, style: BannerStyle) -> Self {
        self.style = style;
        self
    }

    /// Display banner with the configured style
    #[allow(dead_code)]
    pub fn display(&self) {
        self.display_with_style(self.style);
    }

    /// Display banner with specified style
    #[allow(dead_code)]
    pub fn display_with_style(&self, style: BannerStyle) {
        match style {
            BannerStyle::Full => self.display_full(),
            BannerStyle::Mini => self.display_mini(),
            BannerStyle::None => {}
        }
    }

    /// Full 3-line banner with horizontal line, diamond, and version
    fn display_full(&self) {
        let line = "═".repeat(53);
        let version = env!("CARGO_PKG_VERSION");

        println!("{}", format!("  {}", line).dimmed());
        println!("  ◆  GitRecon v{}  ◆", version);
        println!("{}", format!("  {}", line).dimmed());
        println!("{}", "  Enterprise Git Exposure Scanner".dimmed());
        println!();
    }

    /// Compact single-line banner
    fn display_mini(&self) {
        let version = env!("CARGO_PKG_VERSION");
        println!("◆— GitRecon v{}", version);
        println!();
    }

    /// Get the ASCII art representation
    #[allow(dead_code)]
    pub fn art(&self) -> &'static str {
        r"
 ██████╗██╗      ██████╗ ██╗   ██╗██████╗  ██████╗ ███████╗
██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗██╔═══██╗██╔════╝
██║     ██║     ██║   ██║██║   ██║██║  ██║██║   ██║███████╗
██║     ██║     ██║   ██║██║   ██║██║  ██║██║   ██║╚════██║
╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝╚██████╔╝███████║
 ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝
        "
    }

    /// Get the subtitle text
    #[allow(dead_code)]
    pub fn subtitle(&self) -> String {
        self.title
            .clone()
            .unwrap_or_else(|| "Git repository reconnaissance framework".to_string())
    }
}

impl fmt::Display for Banner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.art())?;
        writeln!(f, "{}", self.subtitle())?;
        if self.show_version {
            writeln!(f, "Version {}", env!("CARGO_PKG_VERSION"))?;
        }
        writeln!(f)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_banner_default() {
        let banner = Banner::default();
        assert!(banner.show_version);
        assert!(banner.colored);
        assert!(banner.title.is_none());
        assert_eq!(banner.style, BannerStyle::Full);
    }

    #[test]
    fn test_banner_with_title() {
        let banner = Banner::with_title("Custom Title");
        assert_eq!(banner.title, Some("Custom Title".to_string()));
    }

    #[test]
    fn test_banner_display() {
        let banner = Banner::new();
        let output = format!("{}", banner);
        assert!(output.contains("Git repository reconnaissance framework"));
        assert!(output.contains("Version"));
    }

    #[test]
    fn test_banner_art() {
        let banner = Banner::new();
        let art = banner.art();
        assert!(art.contains("█"));
    }

    #[test]
    fn test_banner_style_full() {
        let banner = Banner::new().style(BannerStyle::Full);
        assert_eq!(banner.style, BannerStyle::Full);
    }

    #[test]
    fn test_banner_style_mini() {
        let banner = Banner::new().style(BannerStyle::Mini);
        assert_eq!(banner.style, BannerStyle::Mini);
    }

    #[test]
    fn test_banner_style_none() {
        let banner = Banner::new().style(BannerStyle::None);
        assert_eq!(banner.style, BannerStyle::None);
    }
}
