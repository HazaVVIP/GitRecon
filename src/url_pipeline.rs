//! URL-target pipeline boundaries.
//!
//! The URL orchestrator owns target-specific detection and reporting; this module
//! owns only the asynchronous Streamer execution stage and its progress callback.

use std::path::PathBuf;
use std::sync::Arc;

use crate::mapper::MapResult;
use crate::reporter::Reporter;
use crate::streamer::{StreamResult, Streamer};

pub(crate) async fn run_stream(
    streamer: &Streamer,
    git_url: &str,
    map_result: &MapResult,
    reporter: &Reporter,
    verbose: bool,
    save_dir: Option<PathBuf>,
) -> StreamResult {
    let progress_reporter = Arc::new(reporter.clone());
    let result = streamer
        .run(
            git_url,
            map_result,
            if verbose {
                Some(Arc::new(move |done: usize, total: usize| {
                    progress_reporter.progress_bar(done, total, 0);
                }))
            } else {
                None
            },
            save_dir,
        )
        .await;
    if verbose {
        println!();
    }
    result
}
