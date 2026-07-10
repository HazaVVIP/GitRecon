//! # Progress Module
//!
//! Progress bars and status indicators for long-running operations.

use std::fmt;
use std::io::{self, Write};
use std::time::{Duration, Instant};
use super::colors::{Color, ColorScheme};

/// Progress bar for displaying task completion
#[derive(Debug)]
#[allow(dead_code)]
pub struct ProgressBar {
    /// Task name/description
    pub task: String,
    /// Total items to process
    pub total: usize,
    /// Current progress count
    pub current: usize,
    /// Start time for ETA calculation
    pub start_time: Instant,
    /// Color scheme
    pub colors: ColorScheme,
    /// Bar width in characters
    pub width: usize,
    /// Last update time (for rate limiting)
    pub last_update: Option<Instant>,
    /// Minimum update interval
    pub update_interval: Duration,
    /// Whether the bar is complete
    pub complete: bool,
    /// Additional status message
    pub status: Option<String>,
}

impl ProgressBar {
    /// Create a new progress bar
    #[allow(dead_code)]
    pub fn new(task: impl Into<String>, total: usize) -> Self {
        Self {
            task: task.into(),
            total,
            current: 0,
            start_time: Instant::now(),
            colors: ColorScheme::default(),
            width: 40,
            last_update: None,
            update_interval: Duration::from_millis(100),
            complete: false,
            status: None,
        }
    }

    /// Set custom width
    #[allow(dead_code)]
    pub fn width(mut self, width: usize) -> Self {
        self.width = width;
        self
    }

    /// Set custom color scheme
    #[allow(dead_code)]
    pub fn colors(mut self, colors: ColorScheme) -> Self {
        self.colors = colors;
        self
    }

    /// Set update interval (to reduce terminal spam)
    #[allow(dead_code)]
    pub fn update_interval(mut self, interval: Duration) -> Self {
        self.update_interval = interval;
        self
    }

    /// Increment progress by one
    #[allow(dead_code)]
    pub fn inc(&mut self) {
        self.inc_by(1);
    }

    /// Increment progress by amount
    #[allow(dead_code)]
    pub fn inc_by(&mut self, amount: usize) {
        self.current = (self.current + amount).min(self.total);
        if self.current >= self.total {
            self.complete = true;
        }
    }

    /// Set current progress directly
    #[allow(dead_code)]
    pub fn set(&mut self, current: usize) {
        self.current = current.min(self.total);
        if self.current >= self.total {
            self.complete = true;
        }
    }

    /// Set a status message
    #[allow(dead_code)]
    pub fn set_status(&mut self, status: impl Into<String>) {
        self.status = Some(status.into());
    }

    /// Clear the status message
    #[allow(dead_code)]
    pub fn clear_status(&mut self) {
        self.status = None;
    }

    /// Get completion percentage (0.0 to 1.0)
    #[allow(dead_code)]
    pub fn fraction(&self) -> f64 {
        if self.total == 0 {
            return 1.0;
        }
        self.current as f64 / self.total as f64
    }

    /// Get completion percentage (0 to 100)
    #[allow(dead_code)]
    pub fn percent(&self) -> f64 {
        self.fraction() * 100.0
    }

    /// Calculate estimated time remaining
    #[allow(dead_code)]
    pub fn eta(&self) -> Option<Duration> {
        if self.total == 0 || self.current == 0 {
            return None;
        }

        let elapsed = self.start_time.elapsed();
        let rate = self.current as f64 / elapsed.as_secs_f64();

        if rate > 0.0 {
            let remaining = (self.total - self.current) as f64 / rate;
            Some(Duration::from_secs_f64(remaining))
        } else {
            None
        }
    }

    /// Format duration as human-readable string
    #[allow(dead_code)]
    pub fn format_duration(d: Duration) -> String {
        let secs = d.as_secs();
        if secs < 60 {
            format!("{}s", secs)
        } else if secs < 3600 {
            format!("{}m {}s", secs / 60, secs % 60)
        } else {
            format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
        }
    }

    /// Check if enough time has passed to update the display
    #[allow(dead_code)]
    pub fn should_update(&self) -> bool {
        match self.last_update {
            None => true,
            Some(last) => self.start_time.elapsed() - (last - self.start_time) >= self.update_interval,
        }
    }

    /// Render the progress bar as a string
    pub fn render(&self) -> String {
        let percent = self.percent();
        let filled = (self.fraction() * self.width as f64) as usize;
        let empty = self.width.saturating_sub(filled);

        let bar = format!(
            "[{}{}]",
            "█".repeat(filled),
            "░".repeat(empty)
        );

        let eta_str = self
            .eta()
            .map(|d| format!(" ETA: {}", Self::format_duration(d)))
            .unwrap_or_default();

        let status_str = self
            .status
            .as_ref()
            .map(|s| format!(" - {}", s))
            .unwrap_or_default();

        format!(
            "{} {} {:.0}%{}{}\n",
            self.colors.muted(&self.task),
            self.colors.primary(&bar),
            percent,
            eta_str,
            status_str
        )
    }

    /// Print the progress bar to stdout
    #[allow(dead_code)]
    pub fn print(&self) {
        if self.should_update() {
            print!("\r{}", self.colors.clear_line());
            print!("{}", self.render());
            io::stdout().flush().unwrap();
        }
    }

    /// Finish the progress bar with a message
    #[allow(dead_code)]
    pub fn finish(mut self, message: Option<&str>) {
        self.complete = true;
        self.current = self.total;

        print!("\r{}", self.colors.clear_line());

        let msg = message.unwrap_or("Complete");
        println!("{} {}", self.colors.success("✔"), self.colors.primary(msg));
    }
}

impl fmt::Display for ProgressBar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.render())
    }
}

/// Multi-progress manager for multiple concurrent bars
#[derive(Debug)]
#[allow(dead_code)]
pub struct Progress {
    /// Collection of progress bars
    pub bars: Vec<ProgressBar>,
    /// Color scheme
    pub colors: ColorScheme,
}

impl Progress {
    /// Create a new multi-progress tracker
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            bars: Vec::new(),
            colors: ColorScheme::default(),
        }
    }

    /// Add a new progress bar
    #[allow(dead_code)]
    pub fn add(&mut self, bar: ProgressBar) -> usize {
        let id = self.bars.len();
        self.bars.push(bar);
        id
    }

    /// Update a specific progress bar
    #[allow(dead_code)]
    pub fn update(&mut self, id: usize, current: usize) {
        if let Some(bar) = self.bars.get_mut(id) {
            bar.set(current);
        }
    }

    /// Increment a specific progress bar
    #[allow(dead_code)]
    pub fn inc(&mut self, id: usize) {
        if let Some(bar) = self.bars.get_mut(id) {
            bar.inc();
        }
    }

    /// Check if all bars are complete
    #[allow(dead_code)]
    pub fn all_complete(&self) -> bool {
        self.bars.iter().all(|b| b.complete)
    }

    /// Render all progress bars
    #[allow(dead_code)]
    pub fn render(&self) -> String {
        self.bars
            .iter()
            .map(|b| b.render())
            .collect::<Vec<_>>()
            .join("")
    }

    /// Print all progress bars
    #[allow(dead_code)]
    pub fn print(&self) {
        // Clear previous output
        for _ in 0..self.bars.len() {
            print!("\r{}", self.colors.clear_line());
            print!("\x1b[1A"); // Move up
        }
        println!("{}", self.render());
    }
}

impl Default for Progress {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple spinner for indeterminate progress
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Spinner {
    /// Current frame index
    pub frame: usize,
    /// Spinner frames
    pub frames: &'static [&'static str],
    /// Message
    pub message: String,
    /// Color
    pub color: Color,
}

impl Spinner {
    /// Create a new spinner
    #[allow(dead_code)]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            frame: 0,
            frames: &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
            message: message.into(),
            color: Color::Cyan,
        }
    }

    /// Advance to next frame
    #[allow(dead_code)]
    pub fn tick(&mut self) {
        self.frame = (self.frame + 1) % self.frames.len();
    }

    /// Render the spinner
    #[allow(dead_code)]
    pub fn render(&self) -> String {
        format!("{} {}", self.frames[self.frame], self.message)
    }

    /// Print the spinner
    #[allow(dead_code)]
    pub fn print(&self) {
        print!("\r\x1b[2K{}", self.render());
        io::stdout().flush().unwrap();
    }
}

impl Default for Spinner {
    fn default() -> Self {
        Self::new("Processing...")
    }
}

impl fmt::Display for Spinner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.render())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_bar_creation() {
        let bar = ProgressBar::new("test", 100);
        assert_eq!(bar.task, "test");
        assert_eq!(bar.total, 100);
        assert_eq!(bar.current, 0);
    }

    #[test]
    fn test_progress_bar_increment() {
        let mut bar = ProgressBar::new("test", 100);
        bar.inc();
        assert_eq!(bar.current, 1);
        bar.inc_by(5);
        assert_eq!(bar.current, 6);
    }

    #[test]
    fn test_progress_bar_fraction() {
        let mut bar = ProgressBar::new("test", 100);
        assert_eq!(bar.fraction(), 0.0);
        bar.set(50);
        assert!((bar.fraction() - 0.5).abs() < 0.001);
        bar.set(100);
        assert_eq!(bar.fraction(), 1.0);
    }

    #[test]
    fn test_progress_bar_complete() {
        let mut bar = ProgressBar::new("test", 100);
        assert!(!bar.complete);
        bar.set(100);
        assert!(bar.complete);
    }

    #[test]
    fn test_duration_format() {
        assert_eq!(ProgressBar::format_duration(Duration::from_secs(5)), "5s");
        assert_eq!(ProgressBar::format_duration(Duration::from_secs(65)), "1m 5s");
        assert_eq!(ProgressBar::format_duration(Duration::from_secs(3665)), "1h 1m");
    }

    #[test]
    fn test_spinner_tick() {
        let mut spinner = Spinner::new("test");
        let initial_frame = spinner.frame;
        spinner.tick();
        assert_eq!(spinner.frame, (initial_frame + 1) % spinner.frames.len());
    }
}
