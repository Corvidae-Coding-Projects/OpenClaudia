use openclaudia::doctor::{self, DoctorConfig, DoctorRequest, DoctorRuntimeSnapshot};

/// Run bounded, evidence-safe diagnostics.
///
/// The standalone command deliberately has no agent runtime, plugin manager,
/// session manager, subprocess, provider client, or writable migration gate.
/// Receipts say when runtime or active evidence is therefore unavailable.
pub fn cmd_doctor(json: bool, active_grants: &[String]) -> anyhow::Result<()> {
    // Validate active authority before reading configuration or other state.
    let request = DoctorRequest::try_new(active_grants)?;
    let config_exists = openclaudia::config::config_file_exists();
    let loaded_config = config_exists
        .then(openclaudia::config::load_config)
        .transpose()
        .ok()
        .flatten();
    let unavailable_config = if config_exists {
        DoctorConfig::Invalid
    } else {
        DoctorConfig::Missing
    };
    let config_state = loaded_config
        .as_ref()
        .map_or(unavailable_config, DoctorConfig::LoadedFromSources);
    let report = doctor::diagnose(config_state, &DoctorRuntimeSnapshot::standalone(), &request);
    report.validate()?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", report.render_human());
    }

    if report.aggregate().is_healthy() {
        Ok(())
    } else {
        anyhow::bail!("doctor aggregate status is {}", report.aggregate().as_str())
    }
}
