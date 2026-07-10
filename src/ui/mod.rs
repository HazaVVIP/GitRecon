//! # UI Module
//!
//! Terminal user interface components for gitrecon.
//!
//! This module provides all visual components used throughout the gitrecon tool,
//! including banners, progress indicators, color schemes, formatted tables, and theme management.

pub mod banner;
pub mod boxes;
pub mod colors;
pub mod progress;
pub mod theme;

pub use banner::{Banner, BannerStyle};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify all public exports are accessible
        let _ = Banner::default();
        let _ = ColorScheme::default();
        let _ = ProgressBar::new("test", 100);
    }
}
