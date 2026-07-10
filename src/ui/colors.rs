//! # Color Scheme Module
//!
//! Terminal color definitions and formatting utilities for consistent theming.
//! Includes severity, confidence, and risk score coloring functions.

use std::fmt;
use colored::{Colorize, ColoredString};

/// ANSI color codes for terminal output
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Color {
    /// Black
    Black = 30,
    /// Red
    Red = 31,
    /// Green
    Green = 32,
    /// Yellow
    Yellow = 33,
    /// Blue
    Blue = 34,
    /// Magenta
    Magenta = 35,
    /// Cyan
    Cyan = 36,
    /// White
    White = 37,
    /// Bright black (gray)
    BrightBlack = 90,
    /// Bright red
    BrightRed = 91,
    /// Bright green
    BrightGreen = 92,
    /// Bright yellow
    BrightYellow = 93,
    /// Bright blue
    BrightBlue = 94,
    /// Bright magenta
    BrightMagenta = 95,
    /// Bright cyan
    BrightCyan = 96,
    /// Bright white
    BrightWhite = 97,
}

impl Color {
    /// Get the ANSI escape sequence for this color
    #[allow(dead_code)]
    pub fn ansi(self) -> String {
        format!("\x1b[{}m", self as u8)
    }

    /// Get the ANSI escape sequence for bright/bold version
    #[allow(dead_code)]
    pub fn bold(self) -> String {
        format!("\x1b[1;{}m", self as u8)
    }

    /// Get the ANSI escape sequence for background color
    #[allow(dead_code)]
    pub fn bg(self) -> String {
        format!("\x1b[{}m", (self as u8) + 10)
    }
}

/// Predefined color scheme for gitrecon UI elements
#[derive(Debug, Clone)]
pub struct ColorScheme {
    /// Primary branding color
    pub primary: Color,
    /// Success/positive indicator color
    pub success: Color,
    /// Warning/caution indicator color
    pub warning: Color,
    /// Error/danger indicator color
    pub error: Color,
    /// Informational color
    pub info: Color,
    /// Muted/secondary text color
    pub muted: Color,
    /// Accent/highlight color
    pub accent: Color,
    /// Whether colors are enabled
    pub enabled: bool,
}

impl Default for ColorScheme {
    fn default() -> Self {
        Self {
            primary: Color::Cyan,
            success: Color::Green,
            warning: Color::Yellow,
            error: Color::Red,
            info: Color::Blue,
            muted: Color::BrightBlack,
            accent: Color::Magenta,
            enabled: true,
        }
    }
}

impl ColorScheme {
    /// Create a new color scheme with default colors
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Disable all colors
    #[allow(dead_code)]
    pub fn plain(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Set a custom primary color
    #[allow(dead_code)]
    pub fn with_primary(mut self, color: Color) -> Self {
        self.primary = color;
        self
    }

    /// Format text with the primary color
    #[allow(dead_code)]
    pub fn primary(&self, text: &str) -> String {
        self.colorize(text, self.primary)
    }

    /// Format text as success
    #[allow(dead_code)]
    pub fn success(&self, text: &str) -> String {
        self.colorize(text, self.success)
    }

    /// Format text as warning
    #[allow(dead_code)]
    pub fn warning(&self, text: &str) -> String {
        self.colorize(text, self.warning)
    }

    /// Format text as error
    #[allow(dead_code)]
    pub fn error(&self, text: &str) -> String {
        self.colorize(text, self.error)
    }

    /// Format text as info
    #[allow(dead_code)]
    pub fn info(&self, text: &str) -> String {
        self.colorize(text, self.info)
    }

    /// Format text as muted
    #[allow(dead_code)]
    pub fn muted(&self, text: &str) -> String {
        self.colorize(text, self.muted)
    }

    /// Format text with accent color
    #[allow(dead_code)]
    pub fn accent(&self, text: &str) -> String {
        self.colorize(text, self.accent)
    }

    /// Format text with bold primary color
    #[allow(dead_code)]
    pub fn bold(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[1m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    /// Format text with dim color
    #[allow(dead_code)]
    pub fn dim(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[2m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    /// Apply color to text
    fn colorize(&self, text: &str, color: Color) -> String {
        if self.enabled {
            format!("{}\x1b[0m", color.bold())
        } else {
            text.to_string()
        }
    }

    /// Reset all formatting
    #[allow(dead_code)]
    pub fn reset(&self) -> &'static str {
        "\x1b[0m"
    }

    /// Clear line
    #[allow(dead_code)]
    pub fn clear_line(&self) -> &'static str {
        "\x1b[2K"
    }

    // ── Severity and confidence coloring helpers ─────────────────────

    /// Centralized color function for severity levels.
    /// CRITICAL and HIGH use bold, MEDIUM uses bright yellow.
    #[allow(dead_code)]
    pub fn severity(sev: &str) -> ColoredString {
        match sev {
            "CRITICAL" => sev.red().bold(),
            "HIGH"     => sev.yellow().bold(),
            "MEDIUM"   => sev.bright_yellow(),
            "LOW"      => sev.cyan(),
            _          => sev.normal(),
        }
    }

    /// Color for confidence labels
    #[allow(dead_code)]
    pub fn confidence(label: &str, text: &str) -> ColoredString {
        match label {
            "CONFIRMED" => text.red().bold(),
            "HIGH"      => text.yellow().bold(),
            "MEDIUM"    => text.bright_yellow(),
            "LOW"       => text.cyan(),
            _           => text.dimmed(),
        }
    }

    /// Color for risk scores
    ///
    /// # Parameters
    /// - `score`: Risk score (0-100)
    /// - `text`: Text to color (typically the score and label)
    #[allow(dead_code)]
    pub fn risk(score: u32, text: &str) -> ColoredString {
        let sev = if score >= 70      { "CRITICAL" }
                  else if score >= 40 { "HIGH" }
                  else if score >= 15 { "MEDIUM" }
                  else                { "CLEAR" };
        match sev {
            "CRITICAL" => text.red().bold(),
            "HIGH"     => text.yellow().bold(),
            "MEDIUM"   => text.bright_yellow(),
            _          => text.green(),
        }
    }

    /// Get the color for a severity level as a Color enum
    #[allow(dead_code)]
    pub fn severity_color(sev: &str) -> Color {
        match sev {
            "CRITICAL" => Color::Red,
            "HIGH"     => Color::Yellow,
            "MEDIUM"   => Color::BrightYellow,
            "LOW"      => Color::Cyan,
            _          => Color::White,
        }
    }

    /// Get the color for a risk score as a Color enum
    #[allow(dead_code)]
    pub fn risk_color(score: u32) -> Color {
        if score >= 70      { Color::Red }
        else if score >= 40 { Color::Yellow }
        else if score >= 15 { Color::BrightYellow }
        else                { Color::Green }
    }

    /// Get the color for a confidence label as a Color enum
    #[allow(dead_code)]
    pub fn confidence_color(label: &str) -> Color {
        match label {
            "CONFIRMED" => Color::Red,
            "HIGH"      => Color::Yellow,
            "MEDIUM"    => Color::BrightYellow,
            "LOW"       => Color::Cyan,
            _           => Color::BrightBlack,
        }
    }
}

/// Helper struct for colored output
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Styled {
    /// The text content
    pub text: String,
    /// The color to apply
    pub color: Option<Color>,
    /// Whether text should be bold
    pub bold: bool,
    /// Whether text should be dimmed
    pub dim: bool,
}

impl Styled {
    /// Create a new styled text
    #[allow(dead_code)]
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            color: None,
            bold: false,
            dim: false,
        }
    }

    /// Set the color
    #[allow(dead_code)]
    pub fn color(mut self, color: Color) -> Self {
        self.color = Some(color);
        self
    }

    /// Set bold
    #[allow(dead_code)]
    pub fn bold(mut self) -> Self {
        self.bold = true;
        self
    }

    /// Set dim
    #[allow(dead_code)]
    pub fn dim(mut self) -> Self {
        self.dim = true;
        self
    }
}

impl fmt::Display for Styled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();

        if let Some(color) = self.color {
            parts.push(color.bold());
        }
        if self.bold {
            parts.push("\x1b[1m".to_string());
        }
        if self.dim {
            parts.push("\x1b[2m".to_string());
        }

        write!(f, "{}{}\x1b[0m", parts.join(""), self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_scheme_default() {
        let scheme = ColorScheme::default();
        assert_eq!(scheme.primary, Color::Cyan);
        assert_eq!(scheme.success, Color::Green);
        assert_eq!(scheme.error, Color::Red);
        assert!(scheme.enabled);
    }

    #[test]
    fn test_color_scheme_plain() {
        let scheme = ColorScheme::new().plain();
        assert!(!scheme.enabled);
    }

    #[test]
    fn test_color_ansi_codes() {
        assert_eq!(Color::Red.ansi(), "\x1b[31m");
        assert_eq!(Color::Blue.bold(), "\x1b[1;34m");
        assert_eq!(Color::Green.bg(), "\x1b[42m");
    }

    #[test]
    fn test_styled_text() {
        let styled = Styled::new("test").color(Color::Red).bold();
        let output = format!("{}", styled);
        assert!(output.contains("test"));
    }

    #[test]
    fn test_severity_colors() {
        let critical = ColorScheme::severity("CRITICAL");
        let high = ColorScheme::severity("HIGH");
        let medium = ColorScheme::severity("MEDIUM");
        let low = ColorScheme::severity("LOW");

        // Just verify they return ColoredString without panic
        let _ = format!("{} {} {} {}", critical, high, medium, low);
    }

    #[test]
    fn test_confidence_colors() {
        let confirmed = ColorScheme::confidence("CONFIRMED", "CONFIRMED");
        let high = ColorScheme::confidence("HIGH", "HIGH");
        let low = ColorScheme::confidence("LOW", "LOW");

        let _ = format!("{} {} {}", confirmed, high, low);
    }

    #[test]
    fn test_risk_colors() {
        let critical = ColorScheme::risk(85, "85/100");
        let high = ColorScheme::risk(50, "50/100");
        let medium = ColorScheme::risk(20, "20/100");
        let clear = ColorScheme::risk(5, "5/100");

        let _ = format!("{} {} {} {}", critical, high, medium, clear);
    }

    #[test]
    fn test_severity_color_enum() {
        assert_eq!(ColorScheme::severity_color("CRITICAL"), Color::Red);
        assert_eq!(ColorScheme::severity_color("HIGH"), Color::Yellow);
        assert_eq!(ColorScheme::severity_color("MEDIUM"), Color::BrightYellow);
        assert_eq!(ColorScheme::severity_color("LOW"), Color::Cyan);
    }

    #[test]
    fn test_risk_color_enum() {
        assert_eq!(ColorScheme::risk_color(85), Color::Red);
        assert_eq!(ColorScheme::risk_color(50), Color::Yellow);
        assert_eq!(ColorScheme::risk_color(20), Color::BrightYellow);
        assert_eq!(ColorScheme::risk_color(5), Color::Green);
    }

    #[test]
    fn test_confidence_color_enum() {
        assert_eq!(ColorScheme::confidence_color("CONFIRMED"), Color::Red);
        assert_eq!(ColorScheme::confidence_color("HIGH"), Color::Yellow);
        assert_eq!(ColorScheme::confidence_color("MEDIUM"), Color::BrightYellow);
        assert_eq!(ColorScheme::confidence_color("LOW"), Color::Cyan);
    }
}
