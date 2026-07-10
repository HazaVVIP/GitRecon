//! # Boxes and Tables Module
//!
//! Box drawing characters and table formatting utilities.

use std::fmt;
use super::colors::ColorScheme;

/// Box drawing characters for terminal borders
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct BoxChars {
    /// Horizontal line
    pub horizontal: char,
    /// Vertical line
    pub vertical: char,
    /// Top-left corner
    pub top_left: char,
    /// Top-right corner
    pub top_right: char,
    /// Bottom-left corner
    pub bottom_left: char,
    /// Bottom-right corner
    pub bottom_right: char,
    /// Left tee
    pub left_tee: char,
    /// Right tee
    pub right_tee: char,
    /// Top tee
    pub top_tee: char,
    /// Bottom tee
    pub bottom_tee: char,
    /// Cross
    pub cross: char,
}

impl Default for BoxChars {
    fn default() -> Self {
        Self::unicode()
    }
}

impl BoxChars {
    /// Unicode box drawing characters (rounded)
    #[allow(dead_code)]
    pub fn unicode() -> Self {
        Self {
            horizontal: '─',
            vertical: '│',
            top_left: '╭',
            top_right: '╮',
            bottom_left: '╰',
            bottom_right: '╯',
            left_tee: '├',
            right_tee: '┤',
            top_tee: '┬',
            bottom_tee: '┴',
            cross: '┼',
        }
    }

    /// Unicode box drawing characters (sharp)
    #[allow(dead_code)]
    pub fn unicode_sharp() -> Self {
        Self {
            horizontal: '─',
            vertical: '│',
            top_left: '┌',
            top_right: '┐',
            bottom_left: '└',
            bottom_right: '┘',
            left_tee: '├',
            right_tee: '┤',
            top_tee: '┬',
            bottom_tee: '┴',
            cross: '┼',
        }
    }

    /// ASCII-only box drawing
    #[allow(dead_code)]
    pub fn ascii() -> Self {
        Self {
            horizontal: '-',
            vertical: '|',
            top_left: '+',
            top_right: '+',
            bottom_left: '+',
            bottom_right: '+',
            left_tee: '+',
            right_tee: '+',
            top_tee: '+',
            bottom_tee: '+',
            cross: '+',
        }
    }

    /// Double-line Unicode box
    #[allow(dead_code)]
    pub fn double() -> Self {
        Self {
            horizontal: '═',
            vertical: '║',
            top_left: '╔',
            top_right: '╗',
            bottom_left: '╚',
            bottom_right: '╝',
            left_tee: '╠',
            right_tee: '╣',
            top_tee: '╦',
            bottom_tee: '╩',
            cross: '╬',
        }
    }
}

/// A simple bordered box for displaying text content
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Box {
    /// Box title (optional)
    pub title: Option<String>,
    /// Box content lines
    pub content: Vec<String>,
    /// Box drawing characters
    pub chars: BoxChars,
    /// Color scheme
    pub colors: ColorScheme,
    /// Padding inside box
    pub padding: usize,
    /// Width (0 = auto)
    pub width: usize,
}

impl Default for Box {
    fn default() -> Self {
        Self {
            title: None,
            content: Vec::new(),
            chars: BoxChars::default(),
            colors: ColorScheme::default(),
            padding: 1,
            width: 0,
        }
    }
}

impl Box {
    /// Create a new box
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a box with a title
    #[allow(dead_code)]
    pub fn with_title(title: impl Into<String>) -> Self {
        Self {
            title: Some(title.into()),
            ..Default::default()
        }
    }

    /// Create a box with content
    #[allow(dead_code)]
    pub fn with_content(content: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            content: content.into_iter().map(|s| s.into()).collect(),
            ..Default::default()
        }
    }

    /// Set box drawing characters
    #[allow(dead_code)]
    pub fn chars(mut self, chars: BoxChars) -> Self {
        self.chars = chars;
        self
    }

    /// Set color scheme
    #[allow(dead_code)]
    pub fn colors(mut self, colors: ColorScheme) -> Self {
        self.colors = colors;
        self
    }

    /// Set padding
    #[allow(dead_code)]
    pub fn padding(mut self, padding: usize) -> Self {
        self.padding = padding;
        self
    }

    /// Set fixed width
    #[allow(dead_code)]
    pub fn width(mut self, width: usize) -> Self {
        self.width = width;
        self
    }

    /// Add a line of content
    #[allow(dead_code)]
    pub fn add_line(&mut self, line: impl Into<String>) {
        self.content.push(line.into());
    }

    /// Calculate the actual width of the box
    fn calculate_width(&self) -> usize {
        if self.width > 0 {
            return self.width;
        }

        let mut max_width = 0;

        if let Some(title) = &self.title {
            max_width = max_width.max(title.len());
        }

        for line in &self.content {
            max_width = max_width.max(line.len());
        }

        max_width + (self.padding * 2)
    }

    /// Render the box as a string
    pub fn render(&self) -> String {
        let width = self.calculate_width();
        let inner_width = width.saturating_sub(2);
        let pad = " ".repeat(self.padding);
        let horizontal = self.chars.horizontal.to_string().repeat(inner_width);

        let mut output = String::new();

        // Top border
        output.push(self.chars.top_left);
        output.push_str(&horizontal);
        output.push(self.chars.top_right);
        output.push('\n');

        // Title (if present)
        if let Some(title) = &self.title {
            output.push(self.chars.vertical);
            output.push_str(&self.colors.bold(&format!(" {} ", title)));
            let remaining = inner_width.saturating_sub(title.len() + 2);
            output.push_str(&" ".repeat(remaining));
            output.push(self.chars.vertical);
            output.push('\n');

            // Separator after title
            output.push(self.chars.left_tee);
            output.push_str(&horizontal);
            output.push(self.chars.right_tee);
            output.push('\n');
        }

        // Content
        for line in &self.content {
            output.push(self.chars.vertical);
            output.push_str(&pad);
            output.push_str(line);
            let remaining = inner_width.saturating_sub(self.padding + line.len());
            output.push_str(&" ".repeat(remaining));
            output.push(self.chars.vertical);
            output.push('\n');
        }

        // Empty padding rows
        for _ in 0..self.padding.saturating_sub(1) {
            output.push(self.chars.vertical);
            output.push_str(&" ".repeat(inner_width));
            output.push(self.chars.vertical);
            output.push('\n');
        }

        // Bottom border
        output.push(self.chars.bottom_left);
        output.push_str(&horizontal);
        output.push(self.chars.bottom_right);

        output
    }
}

impl fmt::Display for Box {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.render())
    }
}

/// Column alignment for table cells
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
#[allow(dead_code)]
pub enum Align {
    /// Left alignment
    #[default]
    Left,
    /// Center alignment
    Center,
    /// Right alignment
    Right,
}


/// Table column configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Column {
    /// Column header
    pub header: String,
    /// Column width
    pub width: usize,
    /// Text alignment
    pub align: Align,
}

impl Column {
    /// Create a new column
    #[allow(dead_code)]
    pub fn new(header: impl Into<String>, width: usize) -> Self {
        Self {
            header: header.into(),
            width,
            align: Align::default(),
        }
    }

    /// Create a new column with alignment
    #[allow(dead_code)]
    pub fn with_align(header: impl Into<String>, width: usize, align: Align) -> Self {
        Self {
            header: header.into(),
            width,
            align,
        }
    }

    /// Set column alignment
    #[allow(dead_code)]
    pub fn align(mut self, align: Align) -> Self {
        self.align = align;
        self
    }
}

/// A table for displaying tabular data
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Table {
    /// Table columns
    pub columns: Vec<Column>,
    /// Table rows (list of cell values)
    pub rows: Vec<Vec<String>>,
    /// Box drawing characters
    pub chars: BoxChars,
    /// Color scheme
    pub colors: ColorScheme,
    /// Show header row
    pub show_header: bool,
    /// Show row borders
    pub row_borders: bool,
}

impl Default for Table {
    fn default() -> Self {
        Self {
            columns: Vec::new(),
            rows: Vec::new(),
            chars: BoxChars::default(),
            colors: ColorScheme::default(),
            show_header: true,
            row_borders: false,
        }
    }
}

impl Table {
    /// Create a new table
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a table with columns
    #[allow(dead_code)]
    pub fn with_columns(columns: Vec<Column>) -> Self {
        Self {
            columns,
            ..Default::default()
        }
    }

    /// Set box drawing characters
    #[allow(dead_code)]
    pub fn chars(mut self, chars: BoxChars) -> Self {
        self.chars = chars;
        self
    }

    /// Set color scheme
    #[allow(dead_code)]
    pub fn colors(mut self, colors: ColorScheme) -> Self {
        self.colors = colors;
        self
    }

    /// Show or hide header
    #[allow(dead_code)]
    pub fn show_header(mut self, show: bool) -> Self {
        self.show_header = show;
        self
    }

    /// Show or hide row borders
    #[allow(dead_code)]
    pub fn row_borders(mut self, show: bool) -> Self {
        self.row_borders = show;
        self
    }

    /// Add a row of data
    #[allow(dead_code)]
    pub fn add_row(&mut self, row: Vec<impl Into<String>>) {
        self.rows.push(row.into_iter().map(|s| s.into()).collect());
    }

    /// Calculate total table width
    #[allow(dead_code)]
    fn total_width(&self) -> usize {
        self.columns.iter().map(|c| c.width).sum::<usize>()
            + self.columns.len() // vertical lines
            + 1 // left border
    }

    /// Format a cell value with alignment
    #[allow(dead_code)]
    fn format_cell(&self, value: &str, width: usize, align: Align) -> String {
        let value_len = value.chars().count();
        if value_len >= width {
            return value.chars().take(width).collect::<String>();
        }

        let padding = width - value_len;
        match align {
            Align::Left => format!("{}{}", value, " ".repeat(padding)),
            Align::Right => format!("{}{}", " ".repeat(padding), value),
            Align::Center => {
                let left = padding / 2;
                let right = padding - left;
                format!("{}{}{}", " ".repeat(left), value, " ".repeat(right))
            }
        }
    }

    /// Render the table as a string
    pub fn render(&self) -> String {
        if self.columns.is_empty() {
            return String::new();
        }

        let mut output = String::new();
        let _horizontal_line: String = self
            .columns
            .iter()
            .map(|c| self.chars.horizontal.to_string().repeat(c.width))
            .collect::<Vec<_>>()
            .join(&self.chars.cross.to_string());

        // Top border
        output.push(self.chars.top_left);
        for (i, col) in self.columns.iter().enumerate() {
            output.push_str(&self.chars.horizontal.to_string().repeat(col.width));
            if i < self.columns.len() - 1 {
                output.push(self.chars.top_tee);
            }
        }
        output.push(self.chars.top_right);
        output.push('\n');

        // Header row
        if self.show_header {
            output.push(self.chars.vertical);
            for col in self.columns.iter() {
                output.push_str(&self.colors.bold(&self.format_cell(
                    &col.header,
                    col.width,
                    col.align,
                )));
                output.push(self.chars.vertical);
            }
            output.push('\n');

            // Header separator
            output.push(self.chars.left_tee);
            for (i, col) in self.columns.iter().enumerate() {
                output.push_str(&self.chars.horizontal.to_string().repeat(col.width));
                if i < self.columns.len() - 1 {
                    output.push(self.chars.cross);
                }
            }
            output.push(self.chars.right_tee);
            output.push('\n');
        }

        // Data rows
        for (row_idx, row) in self.rows.iter().enumerate() {
            output.push(self.chars.vertical);
            for (col_idx, col) in self.columns.iter().enumerate() {
                let value = row.get(col_idx).map(|s| s.as_str()).unwrap_or("");
                output.push_str(&self.format_cell(value, col.width, col.align));
                output.push(self.chars.vertical);
            }
            output.push('\n');

            // Row separator (if enabled and not last row)
            if self.row_borders && row_idx < self.rows.len() - 1 {
                output.push(self.chars.left_tee);
                for (i, col) in self.columns.iter().enumerate() {
                    output.push_str(&self.chars.horizontal.to_string().repeat(col.width));
                    if i < self.columns.len() - 1 {
                        output.push(self.chars.cross);
                    }
                }
                output.push(self.chars.right_tee);
                output.push('\n');
            }
        }

        // Bottom border
        output.push(self.chars.bottom_left);
        for (i, col) in self.columns.iter().enumerate() {
            output.push_str(&self.chars.horizontal.to_string().repeat(col.width));
            if i < self.columns.len() - 1 {
                output.push(self.chars.bottom_tee);
            }
        }
        output.push(self.chars.bottom_right);

        output
    }
}

impl fmt::Display for Table {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.render())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_box_chars_unicode() {
        let chars = BoxChars::unicode();
        assert_eq!(chars.horizontal, '─');
        assert_eq!(chars.vertical, '│');
        assert_eq!(chars.top_left, '╭');
    }

    #[test]
    fn test_box_chars_ascii() {
        let chars = BoxChars::ascii();
        assert_eq!(chars.horizontal, '-');
        assert_eq!(chars.vertical, '|');
        assert_eq!(chars.top_left, '+');
    }

    #[test]
    fn test_box_creation() {
        let test_box = Box::with_title("Test").with_content(vec!["line1", "line2"]);
        assert_eq!(test_box.title, Some("Test".to_string()));
        assert_eq!(test_box.content.len(), 2);
    }

    #[test]
    fn test_box_render() {
        let test_box = Box::with_title("Test").with_content(vec!["line1"]);
        let rendered = test_box.render();
        assert!(rendered.contains("Test"));
        assert!(rendered.contains("line1"));
    }

    #[test]
    fn test_column_creation() {
        let col = Column::new("Header", 10);
        assert_eq!(col.header, "Header");
        assert_eq!(col.width, 10);
        assert_eq!(col.align, Align::Left);
    }

    #[test]
    fn test_table_creation() {
        let table = Table::with_columns(vec![
            Column::new("A", 5),
            Column::new("B", 10),
        ]);
        assert_eq!(table.columns.len(), 2);
    }

    #[test]
    fn test_table_add_row() {
        let mut table = Table::with_columns(vec![
            Column::new("A", 5),
            Column::new("B", 10),
        ]);
        table.add_row(vec!["val1", "val2"]);
        assert_eq!(table.rows.len(), 1);
        assert_eq!(table.rows[0].len(), 2);
    }

    #[test]
    fn test_table_render() {
        let mut table = Table::with_columns(vec![
            Column::new("A", 5),
            Column::new("B", 10),
        ]);
        table.add_row(vec!["1", "2"]);
        let rendered = table.render();
        assert!(rendered.contains("A"));
        assert!(rendered.contains("B"));
    }

    #[test]
    fn test_align_cell() {
        let table = Table::new();
        assert_eq!(table.format_cell("test", 10, Align::Left), "test      ");
        assert_eq!(table.format_cell("test", 10, Align::Right), "      test");
        assert!(table.format_cell("test", 10, Align::Center).contains("test"));
    }
}
