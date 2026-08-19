//! Adapter between binary_scanner output and the common streamer Finding model.

pub(crate) fn binary_findings_to_findings(
    data: &[u8],
    filename: &str,
    max_blob_size: usize,
    include_placeholders: bool,
) -> Vec<crate::streamer::Finding> {
    crate::binary_scanner::scan_binary_blob(data, filename, max_blob_size)
        .into_iter()
        .filter(|(_, match_str, _, _)| {
            include_placeholders || !crate::streamer::is_placeholder(match_str)
        })
        .map(
            |(pattern_id, match_str, context, _source)| crate::streamer::Finding {
                filename: filename.to_string(),
                line: 1,
                pattern_id,
                description: "Secret candidate found in binary content".to_string(),
                severity: "HIGH".to_string(),
                match_str,
                context,
                is_deleted: false,
                commit_sha1: None,
                confidence_adjustment: None,
            },
        )
        .collect()
}

pub(crate) fn is_binary_extension(path: &str) -> bool {
    let ext = path.rsplit('.').next().unwrap_or("").to_lowercase();
    matches!(
        ext.as_str(),
        "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "bmp"
            | "ico"
            | "webp"
            | "tiff"
            | "avif"
            | "zip"
            | "tar"
            | "gz"
            | "bz2"
            | "xz"
            | "7z"
            | "rar"
            | "whl"
            | "jar"
            | "war"
            | "ear"
            | "pdf"
            | "doc"
            | "docx"
            | "xls"
            | "xlsx"
            | "ppt"
            | "pptx"
            | "odt"
            | "ods"
            | "odp"
            | "exe"
            | "dll"
            | "so"
            | "dylib"
            | "bin"
            | "wasm"
            | "o"
            | "a"
            | "lib"
            | "obj"
            | "mp3"
            | "mp4"
            | "wav"
            | "ogg"
            | "flac"
            | "avi"
            | "mov"
            | "mkv"
            | "webm"
            | "m4a"
            | "ttf"
            | "otf"
            | "woff"
            | "woff2"
            | "eot"
            | "pyc"
            | "pyo"
            | "class"
            | "db"
            | "sqlite"
            | "sqlite3"
    )
}
