//! Platforms without a production backend must report the limitation and
//! reject agent execution instead of silently running on the host.

#![cfg(any(target_os = "macos", windows))]
#![allow(clippy::missing_panics_doc)]

#[test]
fn unsupported_production_backend_fails_closed_with_diagnostics() {
    let diagnostics = openclaudia::tools::sandbox_diagnostics();
    assert!(!diagnostics.healthy);
    assert!(!diagnostics.explicit_host_opt_out);
    assert_eq!(diagnostics.network, "denied");
    assert_eq!(diagnostics.syscall_filter, "unavailable");
    assert!(openclaudia::tools::sandbox_preflight().is_err());

    #[cfg(target_os = "macos")]
    assert_eq!(diagnostics.backend, "macos-unavailable");
    #[cfg(windows)]
    assert_eq!(diagnostics.backend, "windows-appcontainer");
}
