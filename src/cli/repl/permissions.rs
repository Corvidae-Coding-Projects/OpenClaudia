/// Execute one explicit `!command` action through the canonical process
/// capability and render its bounded terminal result for the line-oriented
/// frontend. The shared action owns policy, containment, accounting, and
/// grounding; this module is display glue only.
pub fn execute_shell_command(
    run: &openclaudia::tools::ToolRunContext,
    session_key: &str,
    command: &str,
) {
    println!();
    let action = openclaudia::tools::DirectShellAction::new(command, session_key);
    match openclaudia::tools::execute_direct_shell(run, action) {
        Ok(execution) => render_execution(&execution),
        Err(error) => {
            if let Some(execution) = error.partial_execution() {
                render_streams(execution);
            }
            eprintln!("Failed to execute command: {error}");
        }
    }
    println!();
}

fn render_execution(execution: &openclaudia::tools::DirectShellExecution) {
    render_streams(execution);
    match execution.status.as_ref() {
        Some(status) if !status.success() => println!("(terminal status: {status})"),
        None => println!("(terminal status unavailable)"),
        Some(_) => {}
    }
}

fn render_streams(execution: &openclaudia::tools::DirectShellExecution) {
    if !execution.stdout.is_empty() {
        print!("{}", execution.stdout);
    }
    if !execution.stderr.is_empty() {
        eprint!("{}", execution.stderr);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn repl_shell_display_glue_has_no_process_executor() {
        let production = include_str!("permissions.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        assert!(!production.contains("std::process::Command"));
        assert!(!production.contains(".output()"));
        assert!(production.contains("openclaudia::tools::execute_direct_shell"));
    }
}
