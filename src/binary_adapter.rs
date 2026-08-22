//! Adapter between binary_scanner output and the common streamer Finding model.

pub(crate) fn binary_findings_to_findings_with_patterns(
    data: &[u8],
    filename: &str,
    max_blob_size: usize,
    include_placeholders: bool,
    extra_patterns: &[crate::streamer::DynPattern],
) -> Vec<crate::streamer::Finding> {
    crate::binary_scanner::scan_binary_blob_with_patterns(
        data,
        filename,
        max_blob_size,
        extra_patterns,
    )
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
