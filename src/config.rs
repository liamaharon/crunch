use cargo_metadata::camino::{Utf8Path, Utf8PathBuf};
use clap::{Parser, ValueEnum};
use serde::Deserialize;
use std::{
    fs::{self, OpenOptions},
    io::Write,
};

pub const CONFIG_FILE_NAME: &str = "crunch.toml";

const DEFAULT_CONFIG_TEMPLATE: &str = r#"# Project-level defaults for crunch.
# CLI flags override values from this file.
# This file is discovered from the Cargo workspace root.

# Environment variables exported before the remote cargo command runs.
build_env = "RUST_BACKTRACE=1"

# Paths or glob patterns to exclude when syncing the project to the remote host.
exclude = ["target", ".git"]

# Files or directories to copy back after the remote command finishes.
# Each entry is in the form "source:destination".
copy_back = []

# Where crunch should place the project on the remote server.
# Options:
# - "mirror": mirror the local absolute path on the remote machine
# - "tmp": create a temporary directory and remove it afterwards
# - "unique": store the project under ~/crunch-builds/<name>-<hash>
remote_path = "unique"

# Reduce rsync and ssh log output.
quiet = false

# Optional command to run on the remote machine after cargo finishes.
# Example:
# post_cargo = "cd target/release && profile my-binary"
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RemotePathBehavior {
    /// Mirror the local directory structure on the remote server.
    Mirror,
    /// Create a directory in /tmp that is cleaned up when crunch finishes.
    Tmp,
    /// Use ~/crunch-builds.
    Unique,
}

#[derive(Parser, Debug)]
#[command(
    version,
    about,
    trailing_var_arg = true,
    after_long_help = "CONFIG:\n    crunch automatically creates crunch.toml in the Cargo workspace root on first run.\n    CLI flags override config values.\n\nEXAMPLES:\n    crunch -e RUST_LOG=debug check --all-features --all-targets\n    crunch --quiet check\n    crunch test -- --nocapture"
)]
pub struct CliArgs {
    /// Set remote environment variables. RUST_BACKTRACE, CC, LIB, etc.
    #[arg(short = 'e', long)]
    pub build_env: Option<String>,

    /// Path or directory to exclude from the remote server transfer.
    /// Specify multiple entries using delimiter ','.
    ///
    /// Example: `--exclude "target,.git,cat.png,*.lock,mocks/**/*.db"`
    #[arg(long = "exclude", value_delimiter = ',')]
    pub exclude: Option<Vec<String>>,

    /// A command to execute on the machine after the cargo command has finished executing.
    ///
    /// Example: `--post-cargo "cd target/release && profile my-binary"`
    #[arg(long = "post-cargo")]
    pub post_cargo: Option<String>,

    /// Path or directory to sync back from the remote server after all other work has been done.
    /// Each entry should be in the format `source:destination`. Specify multiple entries using delimiter ','.
    ///
    /// Example: `--copy-back "./target/release/cuter-cat.png:.,*.bin:~/my-bins"`
    #[arg(long = "copy-back", value_delimiter = ',')]
    pub copy_back: Option<Vec<String>>,

    /// Where crunch should place the project on the remote server.
    #[arg(long = "remote-path")]
    pub remote_path: Option<RemotePathBehavior>,

    /// Reduce rsync and ssh log output.
    #[arg(short = 'q', long = "quiet", num_args = 0..=1, default_missing_value = "true")]
    pub quiet: Option<bool>,

    /// The cargo command to execute
    ///
    /// Example: `build --release`
    #[arg(required = true, num_args = 1..)]
    pub command: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CrunchConfig {
    build_env: String,
    exclude: Vec<String>,
    #[serde(default)]
    post_cargo: Option<String>,
    #[serde(default)]
    copy_back: Vec<String>,
    remote_path: RemotePathBehavior,
    #[serde(default)]
    quiet: bool,
}

#[derive(Debug)]
pub struct ResolvedArgs {
    pub build_env: String,
    pub exclude: Vec<String>,
    pub post_cargo: Option<String>,
    pub copy_back: Vec<String>,
    pub remote_path: RemotePathBehavior,
    pub quiet: bool,
    pub command: Vec<String>,
}

fn config_path(workspace_root: &Utf8Path) -> Utf8PathBuf {
    workspace_root.join(CONFIG_FILE_NAME)
}

fn parse_config(contents: &str) -> Result<CrunchConfig, toml::de::Error> {
    toml::from_str(contents)
}

fn write_default_config(path: &Utf8Path) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.as_std_path())
        .map_err(|error| format!("Failed to create config '{}': {}", path, error))?;

    file.write_all(DEFAULT_CONFIG_TEMPLATE.as_bytes())
        .map_err(|error| format!("Failed to write config '{}': {}", path, error))
}

pub fn ensure_config_exists(workspace_root: &Utf8Path) -> Result<bool, String> {
    let path = config_path(workspace_root);
    if path.exists() {
        return Ok(false);
    }

    write_default_config(path.as_ref())?;
    Ok(true)
}

fn load_config(workspace_root: &Utf8Path) -> Result<CrunchConfig, String> {
    let path = config_path(workspace_root);
    let contents = fs::read_to_string(path.as_std_path())
        .map_err(|error| format!("Failed to read config '{}': {}", path, error))?;

    parse_config(&contents).map_err(|error| format!("Failed to parse config '{}': {}", path, error))
}

fn merge_args(cli: CliArgs, config: CrunchConfig) -> ResolvedArgs {
    ResolvedArgs {
        build_env: cli.build_env.unwrap_or(config.build_env),
        exclude: cli.exclude.unwrap_or(config.exclude),
        post_cargo: cli.post_cargo.or(config.post_cargo),
        copy_back: cli.copy_back.unwrap_or(config.copy_back),
        remote_path: cli.remote_path.unwrap_or(config.remote_path),
        quiet: cli.quiet.unwrap_or(config.quiet),
        command: cli.command,
    }
}

pub fn resolve_args(cli: CliArgs, workspace_root: &Utf8Path) -> Result<ResolvedArgs, String> {
    let config = load_config(workspace_root)?;
    Ok(merge_args(cli, config))
}

pub fn parse_copy_back_pairs(entries: &[String]) -> Result<Vec<(String, String)>, String> {
    entries
        .iter()
        .map(|entry| {
            let mut parts = entry.splitn(2, ':');
            match (parts.next(), parts.next()) {
                (Some(source), Some(dest)) => Ok((source.to_string(), dest.to_string())),
                _ => Err(format!("Invalid format for --copy-back entry: {entry}")),
            }
        })
        .collect()
}

#[cfg(test)]
fn test_cli_args() -> CliArgs {
    CliArgs {
        build_env: None,
        exclude: None,
        post_cargo: None,
        copy_back: None,
        remote_path: None,
        quiet: None,
        command: vec!["build".to_string()],
    }
}

#[cfg(test)]
fn unique_temp_workspace() -> Utf8PathBuf {
    let unique_dir = format!(
        "crunch-config-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let temp_dir = std::env::temp_dir().join(unique_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    Utf8PathBuf::from_path_buf(temp_dir).unwrap()
}

#[test]
fn parse_config_works() {
    let config = parse_config(
        r#"
build_env = "RUST_LOG=debug"
exclude = ["dist"]
post_cargo = "echo done"
copy_back = ["target/release/app:./bin"]
remote_path = "unique"
quiet = true
"#,
    )
    .unwrap();

    assert_eq!(config.build_env, "RUST_LOG=debug");
    assert_eq!(config.exclude, vec!["dist".to_string()]);
    assert_eq!(config.post_cargo.as_deref(), Some("echo done"));
    assert_eq!(
        config.copy_back,
        vec!["target/release/app:./bin".to_string()]
    );
    assert_eq!(config.remote_path, RemotePathBehavior::Unique);
    assert!(config.quiet);
}

#[test]
fn parse_config_rejects_unknown_fields() {
    let error = parse_config("unknown = true").unwrap_err();

    assert!(error.to_string().contains("unknown field `unknown`"));
}

#[test]
fn parse_config_requires_core_fields() {
    let error = parse_config("exclude = [\"target\"]\nremote_path = \"unique\"").unwrap_err();

    assert!(error.to_string().contains("missing field `build_env`"));
}

#[test]
fn resolve_args_uses_config_when_cli_is_missing() {
    let args = merge_args(
        test_cli_args(),
        CrunchConfig {
            build_env: "RUST_LOG=debug".to_string(),
            exclude: vec!["dist".to_string()],
            post_cargo: Some("echo done".to_string()),
            copy_back: vec!["target/release/app:./bin".to_string()],
            remote_path: RemotePathBehavior::Unique,
            quiet: true,
        },
    );

    assert_eq!(args.build_env, "RUST_LOG=debug");
    assert_eq!(args.exclude, vec!["dist".to_string()]);
    assert_eq!(args.post_cargo.as_deref(), Some("echo done"));
    assert_eq!(args.copy_back, vec!["target/release/app:./bin".to_string()]);
    assert_eq!(args.remote_path, RemotePathBehavior::Unique);
    assert!(args.quiet);
}

#[test]
fn resolve_args_prefers_cli_over_config() {
    let mut cli = test_cli_args();
    cli.build_env = Some("RUST_LOG=trace".to_string());
    cli.post_cargo = Some("echo cli".to_string());
    cli.remote_path = Some(RemotePathBehavior::Tmp);
    cli.quiet = Some(false);

    let args = merge_args(
        cli,
        CrunchConfig {
            build_env: "RUST_LOG=debug".to_string(),
            exclude: vec!["dist".to_string()],
            post_cargo: Some("echo config".to_string()),
            copy_back: vec!["target/release/app:./bin".to_string()],
            remote_path: RemotePathBehavior::Unique,
            quiet: true,
        },
    );

    assert_eq!(args.build_env, "RUST_LOG=trace");
    assert_eq!(args.post_cargo.as_deref(), Some("echo cli"));
    assert_eq!(args.remote_path, RemotePathBehavior::Tmp);
    assert!(!args.quiet);
}

#[test]
fn resolve_args_replaces_config_lists_when_cli_sets_them() {
    let mut cli = test_cli_args();
    cli.exclude = Some(vec!["cli-only".to_string()]);
    cli.copy_back = Some(vec!["remote:local".to_string()]);

    let args = merge_args(
        cli,
        CrunchConfig {
            build_env: "RUST_BACKTRACE=1".to_string(),
            exclude: vec!["config-only".to_string()],
            post_cargo: None,
            copy_back: vec!["config:dest".to_string()],
            remote_path: RemotePathBehavior::Mirror,
            quiet: false,
        },
    );

    assert_eq!(args.exclude, vec!["cli-only".to_string()]);
    assert_eq!(args.copy_back, vec!["remote:local".to_string()]);
}

#[test]
fn config_path_uses_workspace_root() {
    let path = config_path(Utf8Path::new("/tmp/workspace"));

    assert_eq!(path, Utf8PathBuf::from("/tmp/workspace/crunch.toml"));
}

#[test]
fn ensure_config_exists_creates_default_config_once() {
    let workspace_root = unique_temp_workspace();

    assert!(ensure_config_exists(workspace_root.as_ref()).unwrap());
    assert!(!ensure_config_exists(workspace_root.as_ref()).unwrap());

    let config_contents =
        fs::read_to_string(workspace_root.join(CONFIG_FILE_NAME).as_std_path()).unwrap();
    assert_eq!(config_contents, DEFAULT_CONFIG_TEMPLATE);

    fs::remove_dir_all(workspace_root.as_std_path()).unwrap();
}

#[test]
fn parse_copy_back_pairs_works() {
    let pairs = parse_copy_back_pairs(&["remote/path:./local".to_string()]).unwrap();

    assert_eq!(
        pairs,
        vec![("remote/path".to_string(), "./local".to_string())]
    );
}

#[test]
fn parse_copy_back_pairs_rejects_invalid_entries() {
    let error = parse_copy_back_pairs(&["remote-only".to_string()]).unwrap_err();

    assert_eq!(error, "Invalid format for --copy-back entry: remote-only");
}
