use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Banner display style for output formatting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum BannerStyle {
    /// Minimal banner - single line
    Minimal,
    /// Standard banner - box style
    #[default]
    Standard,
    /// Full banner - ASCII art style
    Full,
    /// No banner - silent mode
    None,
}

/// Color scheme for severity levels and status types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorScheme {
    /// Critical severity color (red/crimson)
    pub critical: String,
    /// High severity color (orange)
    pub high: String,
    /// Medium severity color (yellow)
    pub medium: String,
    /// Low severity color (blue/cyan)
    pub low: String,
    /// Informational message color
    pub info: String,
    /// Success message color (green)
    pub success: String,
}

impl Default for ColorScheme {
    fn default() -> Self {
        Self {
            critical: "red".to_string(),
            high: "yellow".to_string(),
            medium: "yellow".to_string(),
            low: "blue".to_string(),
            info: "cyan".to_string(),
            success: "green".to_string(),
        }
    }
}

/// Main theme configuration struct
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Theme {
    /// Banner display style
    pub banner_style: BannerStyle,
    /// Color scheme for output
    pub colors: ColorScheme,
    /// Compact output mode (reduced verbosity)
    pub compact: bool,
    /// Use Unicode characters (enhanced symbols)
    pub unicode: bool,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            banner_style: BannerStyle::default(),
            colors: ColorScheme::default(),
            compact: false,
            unicode: true,
        }
    }
}

impl Theme {
    /// Get the default theme configuration file path
    #[allow(dead_code)]
    pub fn config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|dir| dir.join("gitrecon").join("theme.toml"))
    }

    /// Load theme from configuration file, falling back to defaults
    pub fn load() -> Self {
        if let Some(config_path) = Self::config_path() {
            if let Ok(content) = fs::read_to_string(&config_path) {
                if let Ok(theme) = toml::from_str::<Theme>(&content) {
                    return theme;
                }
            }
        }
        Self::default()
    }

    /// Save theme to configuration file
    #[allow(dead_code)]
    pub fn save(&self) -> Result<(), String> {
        let config_path = Self::config_path().ok_or("Failed to determine config directory")?;

        // Create parent directory if it doesn't exist
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create config directory: {}", e))?;
        }

        // Serialize theme to TOML
        let toml_content = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize theme: {}", e))?;

        // Write to file
        fs::write(&config_path, toml_content)
            .map_err(|e| format!("Failed to write theme file: {}", e))?;

        Ok(())
    }

    /// Create a new theme with custom settings
    #[allow(dead_code)]
    pub fn new(
        banner_style: BannerStyle,
        colors: ColorScheme,
        compact: bool,
        unicode: bool,
    ) -> Self {
        Self {
            banner_style,
            colors,
            compact,
            unicode,
        }
    }

    /// Reset theme to defaults
    #[allow(dead_code)]
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_theme() {
        let theme = Theme::default();
        assert_eq!(theme.banner_style, BannerStyle::Standard);
        assert_eq!(theme.colors.critical, "red");
        assert_eq!(theme.colors.success, "green");
        assert!(!theme.compact);
        assert!(theme.unicode);
    }

    #[test]
    fn test_theme_serialization() {
        let theme = Theme::default();
        let toml_str = toml::to_string(&theme).unwrap();
        let deserialized: Theme = toml::from_str(&toml_str).unwrap();
        assert_eq!(theme.banner_style, deserialized.banner_style);
        assert_eq!(theme.colors.critical, deserialized.colors.critical);
    }

    #[test]
    fn test_banner_style_variants() {
        assert_ne!(BannerStyle::Minimal, BannerStyle::Standard);
        assert_ne!(BannerStyle::Full, BannerStyle::None);
    }

    #[test]
    fn test_color_scheme_default() {
        let colors = ColorScheme::default();
        assert!(!colors.critical.is_empty());
        assert!(!colors.high.is_empty());
        assert!(!colors.medium.is_empty());
        assert!(!colors.low.is_empty());
        assert!(!colors.info.is_empty());
        assert!(!colors.success.is_empty());
    }
}
