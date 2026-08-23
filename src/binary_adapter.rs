//! Adapter between binary_scanner output and the common streamer Finding model.

pub(crate) fn binary_tuples_to_findings(
    findings: Vec<(String, String, String, String)>,
    filename: &str,
    include_placeholders: bool,
    extra_patterns: &[crate::streamer::DynPattern],
) -> Vec<crate::streamer::Finding> {
    findings
        .into_iter()
        .filter(|(_, match_str, _, _)| {
            include_placeholders || !crate::streamer::is_placeholder(match_str)
        })
        .map(|(pattern_id, match_str, context, _source)| {
            let metadata = extra_patterns
                .iter()
                .find(|pattern| pattern.id == pattern_id);
            crate::streamer::Finding {
                filename: filename.to_string(),
                line: 1,
                description: metadata
                    .map(|pattern| pattern.desc.clone())
                    .unwrap_or_else(|| "Secret candidate found in binary content".to_string()),
                severity: metadata
                    .map(|pattern| pattern.sev.clone())
                    .unwrap_or_else(|| "HIGH".to_string()),
                pattern_id,
                match_str,
                context,
                is_deleted: false,
                commit_sha1: None,
                confidence_adjustment: None,
            }
        })
        .collect()
}

pub(crate) use crate::binary_scanner::is_binary_extension;
