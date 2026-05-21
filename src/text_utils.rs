//! text_utils.rs
//! Shared UTF-8 safe text helpers.

/// Return at most `max_chars` Unicode scalar values from `text`,
/// never splitting inside a UTF-8 character boundary.
pub fn truncate_utf8(text: &str, max_chars: usize) -> &str {
    if max_chars == 0 {
        return "";
    }
    match text.char_indices().nth(max_chars) {
        Some((idx, _)) => &text[..idx],
        None => text,
    }
}

#[cfg(test)]
mod tests {
    use super::truncate_utf8;

    #[test]
    fn truncate_utf8_keeps_ascii_prefix() {
        assert_eq!(truncate_utf8("abcdef", 3), "abc");
    }

    #[test]
    fn truncate_utf8_keeps_multibyte_boundary() {
        assert_eq!(truncate_utf8("ab─cd", 3), "ab─");
        assert_eq!(truncate_utf8("你好世界", 2), "你好");
        assert_eq!(truncate_utf8("key🔐value", 4), "key🔐");
    }

    #[test]
    fn truncate_utf8_handles_short_and_zero() {
        assert_eq!(truncate_utf8("ok", 10), "ok");
        assert_eq!(truncate_utf8("ok", 0), "");
    }
}
