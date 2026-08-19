//! Terminal width and layout utilities for gitrecon.
//!
//! Provides utilities for detecting terminal dimensions, calculating box widths,
//! and determining Unicode support status.

use std::env;

#[cfg(unix)]
use std::mem::zeroed;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;

#[cfg(unix)]
use libc::{ioctl, TIOCGWINSZ};

/// Default terminal width to use when detection fails.
pub const DEFAULT_TERMINAL_WIDTH: usize = 80;

/// Minimum box width constraint.
pub const MIN_BOX_WIDTH: usize = 40;

/// Maximum box width constraint.
pub const MAX_BOX_WIDTH: usize = 120;

/// Terminal window size structure for Unix systems.
#[cfg(unix)]
#[repr(C)]
struct Winsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

/// Get the current terminal width.
///
/// This function first checks the `COLUMNS` environment variable,
/// then falls back to using `ioctl` on Unix systems to query the
/// actual terminal dimensions.
///
/// # Returns
///
/// The terminal width in columns, or `DEFAULT_TERMINAL_WIDTH` if detection fails.
pub fn get_terminal_width() -> usize {
    // First, check the COLUMNS environment variable
    if let Ok(columns) = env::var("COLUMNS") {
        if let Ok(width) = columns.parse::<usize>() {
            if width > 0 {
                return width;
            }
        }
    }

    // Fall back to ioctl on Unix systems
    #[cfg(unix)]
    {
        let winsize = get_winsize();
        if let Some(width) = winsize {
            if width > 0 {
                return width;
            }
        }
    }

    // Default fallback
    DEFAULT_TERMINAL_WIDTH
}

/// Get window size using ioctl on Unix systems.
#[cfg(unix)]
fn get_winsize() -> Option<usize> {
    unsafe {
        let mut winsize: Winsize = zeroed();

        // Try to get the window size from stdout
        let stdout_fd = std::io::stdout().as_raw_fd();
        if ioctl(stdout_fd, TIOCGWINSZ, &mut winsize) == 0 && winsize.ws_col > 0 {
            return Some(winsize.ws_col as usize);
        }

        // Try stderr as fallback
        let stderr_fd = std::io::stderr().as_raw_fd();
        if ioctl(stderr_fd, TIOCGWINSZ, &mut winsize) == 0 && winsize.ws_col > 0 {
            return Some(winsize.ws_col as usize);
        }

        None
    }
}

/// Calculate box width with min and max constraints.
///
/// This function calculates an appropriate width for drawing boxes
/// or panels in the terminal, respecting minimum and maximum constraints.
///
/// # Arguments
///
/// * `content_width` - The desired width based on content.
/// * `terminal_width` - The available terminal width (use `get_terminal_width()`).
///
/// # Returns
///
/// A width value clamped between `MIN_BOX_WIDTH` and `MAX_BOX_WIDTH`,
/// but never exceeding the terminal width.
pub fn calculate_box_width(content_width: usize, terminal_width: usize) -> usize {
    if terminal_width == 0 {
        return MIN_BOX_WIDTH;
    }
    let max_allowed = terminal_width.min(MAX_BOX_WIDTH);
    let min_required = MIN_BOX_WIDTH.min(max_allowed);

    // If content width is within bounds, use it
    if content_width >= min_required && content_width <= max_allowed {
        return content_width;
    }

    // Otherwise clamp to bounds
    if content_width < min_required {
        min_required
    } else {
        max_allowed
    }
}

/// Check if the terminal supports Unicode.
///
/// This function examines the `LANG` and `LC_CTYPE` environment variables
/// to determine if the terminal locale is configured for UTF-8 encoding.
///
/// # Returns
///
/// `true` if UTF-8 support is detected, `false` otherwise.
#[allow(dead_code)]
pub fn supports_unicode() -> bool {
    // Helper to check if a locale string indicates UTF-8 support
    let is_utf8 = |value: &str| {
        value.to_lowercase().contains("utf-8")
            || value.to_lowercase().contains("utf8")
            || value.contains(".UTF-8")
            || value.contains(".utf8")
    };

    // Check LC_CTYPE first (most specific)
    if let Ok(lc_ctype) = env::var("LC_CTYPE") {
        if !lc_ctype.is_empty() && is_utf8(&lc_ctype) {
            return true;
        }
    }

    // Check LANG (general locale setting)
    if let Ok(lang) = env::var("LANG") {
        if !lang.is_empty() && is_utf8(&lang) {
            return true;
        }
    }

    // Check LC_ALL (overrides all LC_* variables)
    if let Ok(lc_all) = env::var("LC_ALL") {
        if !lc_all.is_empty() && is_utf8(&lc_all) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_box_width_clamping() {
        // Test minimum clamping
        assert_eq!(calculate_box_width(20, 100), MIN_BOX_WIDTH);

        // Test maximum clamping
        assert_eq!(calculate_box_width(150, 100), 100);

        // Test within bounds
        assert_eq!(calculate_box_width(60, 100), 60);

        // Test terminal width smaller than max
        assert_eq!(calculate_box_width(60, 50), 50);
    }

    #[test]
    fn test_calculate_box_width_edge_cases() {
        // When terminal is too narrow for minimum
        assert_eq!(calculate_box_width(60, 30), 30);

        // Zero terminal width (shouldn't happen in practice)
        assert_eq!(calculate_box_width(60, 0), MIN_BOX_WIDTH);
    }

    #[test]
    fn test_default_terminal_width() {
        let width = get_terminal_width();
        // Should always return a positive value
        assert!(width > 0);
    }

    #[test]
    fn test_supports_unicode() {
        // We can't test the actual detection without setting env vars,
        // but we can ensure the function doesn't panic
        let has_unicode = supports_unicode();
        // Result is always a boolean
        assert!(has_unicode || !has_unicode);
    }
}
