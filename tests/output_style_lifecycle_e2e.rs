//! Authority-boundary coverage for output-style configuration.
//!
//! Output preferences are user-owned configuration. A repository-local
//! `.openclaudia/output-style.md` must never acquire automatic prompt authority.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]

use openclaudia::output_style::load_output_style_context;
use std::sync::{Mutex, OnceLock};

fn cwd_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn repository_output_style_is_ignored() {
    let _cwd_lock = cwd_lock();
    let directory = tempfile::tempdir().expect("tempdir");
    let previous = std::env::current_dir().expect("cwd");
    let project_config = directory.path().join(".openclaudia");
    std::fs::create_dir_all(&project_config).expect("project config");

    let sentinel = "REPOSITORY_OUTPUT_STYLE_MUST_NOT_HAVE_PROMPT_AUTHORITY_7C3C3A9E";
    std::fs::write(project_config.join("output-style.md"), sentinel).expect("project style");
    std::env::set_current_dir(directory.path()).expect("set cwd");

    let loaded = load_output_style_context().map(|item| item.content().to_string());

    std::env::set_current_dir(previous).expect("restore cwd");
    assert_ne!(loaded.as_deref(), Some(sentinel));
}
