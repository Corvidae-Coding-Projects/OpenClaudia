//! `OpenClaudia` - Open-source universal agent harness
//!
//! Provides Claude Code-like capabilities for any AI agent.
//!
//! This library exposes the core functionality of `OpenClaudia` for both
//! the CLI binary and integration testing.

#![recursion_limit = "256"]

/// Default max output tokens for chat completions when not specified by config.
pub const DEFAULT_MAX_TOKENS: u32 = 4096;

pub mod acp;
pub mod auto_learn;
pub mod capability_evidence;
pub mod claude_credentials;
pub mod codex_credentials;
pub mod compaction;
pub mod config;
pub mod context;
pub mod coordinator;
pub mod decision;
pub mod doctor;
pub mod evidence;
mod evidence_freshness;
pub mod file_error;
mod file_types;
pub mod final_gate;
pub mod grounded_loop;
pub mod guardrails;
pub mod hooks;
pub mod keybindings;
pub mod ledger;
pub mod mcp;
pub mod mcp_elicitation;
pub mod mcp_inprocess;
pub mod mcp_oauth;
pub mod memdir;
pub mod memory;
pub mod migrations;
pub mod modes;
pub mod oauth;
pub mod output_style;
pub mod permissions;
pub mod persistence;
pub mod pipeline;
pub mod plugins;
pub mod prompt;
pub mod provider_budget;
pub mod provider_transport;
pub mod providers;
pub mod proxy;
pub mod runtime;
pub mod secrets;
pub mod services;
pub mod session;
pub mod skills;
pub mod slash_commands;
pub mod state;
pub mod subagent;
pub mod task_graph;
pub mod task_spec;
pub mod team_memory;
pub mod thinking;
pub mod tools;
pub mod transcript;
pub mod tui;
pub mod vdd;
pub mod web;
