//! Runtime acceptance for S-012 lifecycle-service reachability.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]

use std::collections::BTreeMap;
use std::process::{Command, Output};

use openclaudia::capability_evidence::{CapabilityEvidenceBundle, CapabilityMaturity};
use openclaudia::services::{
    lifecycle_service_catalog, validate_lifecycle_service_catalog, LifecycleServiceClassification,
    LifecycleServiceId,
};

fn isolated_command(project: &tempfile::TempDir, home: &tempfile::TempDir) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_openclaudia"));
    command
        .env_clear()
        .current_dir(project.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("XDG_DATA_HOME", home.path().join(".local/share"));
    command
}

fn combined_output(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn every_service_has_one_unambiguous_audited_disposition() {
    validate_lifecycle_service_catalog().expect("bundled lifecycle catalog");

    let actual = lifecycle_service_catalog()
        .iter()
        .map(|registration| (registration.id(), registration.classification()))
        .collect::<BTreeMap<_, _>>();
    let expected = BTreeMap::from([
        (
            LifecycleServiceId::Analytics,
            LifecycleServiceClassification::Wired,
        ),
        (
            LifecycleServiceId::FeatureRollout,
            LifecycleServiceClassification::Unavailable,
        ),
        (
            LifecycleServiceId::BackgroundJobs,
            LifecycleServiceClassification::Unavailable,
        ),
        (
            LifecycleServiceId::AutoCompaction,
            LifecycleServiceClassification::Wired,
        ),
        (
            LifecycleServiceId::PluginMcpRuntime,
            LifecycleServiceClassification::Wired,
        ),
        (
            LifecycleServiceId::PluginMcpShadowRegistry,
            LifecycleServiceClassification::Experimental,
        ),
        (
            LifecycleServiceId::ProjectMemory,
            LifecycleServiceClassification::Wired,
        ),
        (
            LifecycleServiceId::TeamMemory,
            LifecycleServiceClassification::Wired,
        ),
        (
            LifecycleServiceId::Guardrails,
            LifecycleServiceClassification::Wired,
        ),
        (
            LifecycleServiceId::EnterprisePolicy,
            LifecycleServiceClassification::Wired,
        ),
        (
            LifecycleServiceId::ToolExecutor,
            LifecycleServiceClassification::Wired,
        ),
        (
            LifecycleServiceId::LspPool,
            LifecycleServiceClassification::Wired,
        ),
        (
            LifecycleServiceId::LspDiagnostics,
            LifecycleServiceClassification::Wired,
        ),
        (
            LifecycleServiceId::RateLimitFailureInjection,
            LifecycleServiceClassification::TestOnly,
        ),
    ]);

    assert_eq!(actual, expected);
}

#[test]
fn wired_services_publish_a_complete_construction_to_shutdown_path() {
    for registration in lifecycle_service_catalog() {
        match registration.classification() {
            LifecycleServiceClassification::Wired => {
                let path = registration.path().expect("wired path");
                assert!(!path.construct().is_empty());
                assert!(!path.consume().is_empty());
                assert!(!path.shutdown().is_empty());
                assert!(registration.follow_up().is_none());
            }
            LifecycleServiceClassification::Unavailable => {
                assert!(registration.path().is_none());
                assert!(registration.follow_up().is_some());
            }
            LifecycleServiceClassification::Disabled
            | LifecycleServiceClassification::Experimental
            | LifecycleServiceClassification::TestOnly => {
                assert!(registration.path().is_none());
            }
        }
        assert!(!registration.reason().is_empty());
    }
}

#[test]
fn generic_feature_flag_environment_is_rejected_at_process_boundary() {
    let project = tempfile::tempdir().expect("project");
    let home = tempfile::tempdir().expect("home");
    let directory = project.path().join(".openclaudia");
    std::fs::create_dir_all(&directory).expect("config directory");
    std::fs::write(directory.join("config.yaml"), "{}\n").expect("minimal config file");
    let output = isolated_command(&project, &home)
        .arg("config")
        .env("OPENCLAUDIA_FEATURE_UNDECLARED", "true")
        .output()
        .expect("config command");

    assert!(!output.status.success());
    let text = combined_output(&output);
    assert!(text.contains("unknown OpenClaudia environment variable"));
    assert!(text.contains("OPENCLAUDIA_FEATURE_UNDECLARED"));
}

#[test]
fn configured_team_memory_fails_visibly_instead_of_being_ignored() {
    let project = tempfile::tempdir().expect("project");
    let home = tempfile::tempdir().expect("home");
    let directory = project.path().join(".openclaudia");
    std::fs::create_dir_all(&directory).expect("config directory");
    std::fs::write(
        directory.join("config.yaml"),
        "memory:\n  team_memory_path: shared-team-memory\n",
    )
    .expect("config file");

    let output = isolated_command(&project, &home)
        .arg("config")
        .output()
        .expect("config command");
    assert!(!output.status.success());
    let text = combined_output(&output);
    assert!(text.contains("memory.team_memory_path is unsupported"));
    assert!(text.contains("filesystem path is never"));
    assert!(text.contains("authenticated team authority"));
    assert!(text.contains("configure memory.team_id after host enrollment"));
    assert!(text.contains("signed service descriptor"));
}

#[test]
fn environment_configured_team_memory_fails_at_the_same_boundary() {
    let project = tempfile::tempdir().expect("project");
    let home = tempfile::tempdir().expect("home");
    let directory = project.path().join(".openclaudia");
    std::fs::create_dir_all(&directory).expect("config directory");
    std::fs::write(directory.join("config.yaml"), "{}\n").expect("minimal config file");

    let output = isolated_command(&project, &home)
        .arg("config")
        .env(
            "OPENCLAUDIA_MEMORY__TEAM_MEMORY_PATH",
            project.path().join("shared-team-memory"),
        )
        .output()
        .expect("config command");
    assert!(!output.status.success());
    let text = combined_output(&output);
    assert!(text.contains("memory.team_memory_path is unsupported"));
    assert!(text.contains("filesystem path is never"));
    assert!(text.contains("authenticated team authority"));
    assert!(text.contains("configure memory.team_id after host enrollment"));
    assert!(text.contains("signed service descriptor"));
}

#[test]
fn capability_registry_carries_the_internal_reachability_record() {
    let bundle = CapabilityEvidenceBundle::bundled().expect("validated capability bundle");
    let capability = bundle
        .registry()
        .capability("lifecycle-service-reachability")
        .expect("S-012 capability record");
    assert_eq!(capability.maturity(), CapabilityMaturity::Partial);
    assert_eq!(capability.entrypoints().len(), 1);
    assert_eq!(
        capability.entrypoints()[0].invocation(),
        "services::lifecycle_service_catalog"
    );
}
