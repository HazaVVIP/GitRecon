//! Shared policy values for text, multiline, entropy, and binary scanning.

/// Immutable policy passed through detector pipelines.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct ScanPolicy<'a> {
    pub(crate) entropy_threshold: f64,
    pub(crate) false_positive_keywords: &'a [&'a str],
    pub(crate) include_placeholders: bool,
}

impl<'a> ScanPolicy<'a> {
    pub(crate) fn normal(entropy_threshold: f64, false_positive_keywords: &'a [&'a str]) -> Self {
        Self {
            entropy_threshold,
            false_positive_keywords,
            include_placeholders: false,
        }
    }

    pub(crate) fn exhaustive(
        entropy_threshold: f64,
        false_positive_keywords: &'a [&'a str],
    ) -> Self {
        Self {
            entropy_threshold,
            false_positive_keywords,
            include_placeholders: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ScanPolicy;

    #[test]
    fn constructors_encode_placeholder_policy() {
        let keywords = ["example"];
        assert!(!ScanPolicy::normal(4.5, &keywords).include_placeholders);
        assert!(ScanPolicy::exhaustive(4.5, &keywords).include_placeholders);
    }
}
