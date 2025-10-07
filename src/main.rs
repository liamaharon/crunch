//! Turbocharge your Rust workflow.
//!
//! crunch seamlessly integrates cutting-edge hardware into your local development environment.


mod config;
use config::AppConfig;
use cargo_metadata::camino::Utf8PathBuf;
use clap::{command, Parser, ValueEnum};
use log::{debug, error, info};
use std::{
    hash::{DefaultHasher, Hash, Hasher},
    process::{exit, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone)]
pub struct Remote {
    pub name: String,
    pub host: String,
    pub ssh_port: u16,
    pub crunch_dir: String,
    pub env: String,
}

#[derive(Debug, Clone, ValueEnum)]
enum RemotePathBehavior {
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
    after_long_help = "EXAMPLES:\n    crunch -v build --release\n    crunch -e RUST_LOG=debug check --all-features --all-targets\n    crunch test -- --nocapture"
)]
struct Args {
    /// Verbose flag (must come before cargo command)
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Override timeout seconds for this run
    #[arg(long, global = true)]
    timeout_secs: Option<u64>,

    /// Where crunch should place the project on the remote server.
    #[arg(long = "remote-path", required = false, default_value = "mirror", global = true)]
    remote_path: RemotePathBehavior,

    /// Optional: print final effective config and exit (debug)
    #[arg(long, global = true)]
    print_config: bool,
    /// Set remote environment variables. RUST_BACKTRACE, CC, LIB, etc.
    #[arg(
        short = 'e',
        long,
        required = false,
        default_value = "RUST_BACKTRACE=1",
        global = true
    )]
    build_env: String,

    /// Path or directory to exclude from the remote server transfer.
    /// Specify multiple entries using delimiter ','.
    ///
    /// By default the `target` and `.git` directories are excluded.
    ///
    /// Example: `--exclude "target,.git,cat.png,*.lock,mocks/**/*.db"`
    #[arg(
        long = "exclude",
        required = false,
        value_delimiter = ',',
        default_value = "target,.git",
        global = true
    )]
    exclude: Vec<String>,

    /// A command to execute on the machine after the cargo command has finished executing.
    ///
    /// Example: `--post-cargo "cd target/release && profile my-binary"`
    #[arg(long = "post-cargo", required = false, global = true)]
    post_cargo: Option<String>,

    /// Path or directory to sync back from the remote server after all other work has been done.
    /// Each entry should be in the format `source:destination`. Specify multiple entries using delimiter ','.
    ///
    /// Example: `--copy-back "./target/release/cuter-cat.png:.,*.bin:~/my-bins"`
    #[arg(long = "copy-back", required = false, value_delimiter = ',', global = true)]
    copy_back: Vec<String>,

    /// The cargo command to execute
    ///
    /// Example: `build --release`
    #[arg(required = true, num_args = 1..)]
    command: Vec<String>,
}
fn uid_from_path(path: &Utf8PathBuf) -> u64 {
    let mut hasher = DefaultHasher::new();
    path.as_str().hash(&mut hasher);
    hasher.finish()
}

fn main() {
    
    let cfg = AppConfig::load_config()
        .unwrap_or_else(|e| {
            eprintln!("Warning: Failed to load configuration: {}", e);
            eprintln!("Using default values...");
            // Return defaults if config loading fails
            AppConfig {
                remote_path: "mirror".to_string(),
                timeout_secs: 30,
                verbose: false,
                exclude: "target,.git".to_string(),
                build_env: "RUST_BACKTRACE=1".to_string(),
            }
        });

    // Parse command line args - these will override config
    let mut args = Args::parse();

    // Apply config values if CLI args are at their defaults
    if args.remote_path.matches_default() {
        args.remote_path = parse_remote_path_behavior(&cfg.remote_path);
    }

    if args.timeout_secs.is_none() {
        args.timeout_secs = Some(cfg.timeout_secs);
    }

    if !args.verbose {
        args.verbose = cfg.verbose;
    }

    if args.exclude.len() == 2 && args.exclude[0] == "target" && args.exclude[1] == ".git" {
        args.exclude = cfg.exclude.split(',').map(|s| s.trim().to_string()).collect();
    }

    if args.build_env == "RUST_BACKTRACE=1" {
        args.build_env = cfg.build_env.clone();
    }

    // Initialize logger after merging verbose flag
    let log_level = if args.verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    env_logger::builder()
        .filter_level(log_level)
        .init();

    debug!("Loaded config: {:?}", &cfg);
    debug!("Final args after config merge: {:?}", &args);

    // Handle --print-config flag
    if args.print_config {
        println!("Final effective configuration:");
        println!("  remote_path: {:?}", args.remote_path);
        println!("  timeout_secs: {:?}", args.timeout_secs);
        println!("  verbose: {}", args.verbose);
        println!("  exclude: {:?}", args.exclude);
        println!("  build_env: {}", args.build_env);
        println!("  command: {:?}", args.command);
        return;
    }


    let copy_back_pairs: Vec<(String, String)> = args
        .copy_back
        .into_iter()
        .filter_map(|entry| {
            let mut parts = entry.splitn(2, ':');
            match (parts.next(), parts.next()) {
                (Some(source), Some(dest)) => Some((source.to_string(), dest.to_string())),
                _ => {
                    panic!("Invalid format for --copy-back entry: {entry}");
                }
            }
        })
        .collect();

    // Run it once redirecting logs to terminal to ensure if something needs to be installed, user
    // sees it.
    Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .stderr(Stdio::inherit())
        .output()
        .unwrap_or_else(|e| {
            error!("Failed to run cargo command remotely (error: {})", e);
            exit(-5);
        });

    // Now run it again to get the workspace_root.
    let manifest_path = extract_manifest_path(&args.command).unwrap_or("Cargo.toml".to_string());
    let mut metadata_cmd = cargo_metadata::MetadataCommand::new();
    metadata_cmd.manifest_path(manifest_path).no_deps();
    let project_metadata = metadata_cmd.exec().unwrap();
    let project_dir = project_metadata.workspace_root;

    let remote = Remote {
        name: "crunch".to_string(),
        host: "crunch".to_string(),
        ssh_port: 22,
        crunch_dir: "~/crunch-builds".to_string(),
        env: "~/.profile".to_string(),
    };

    let build_server = remote.host;

    let build_path = match args.remote_path {
        RemotePathBehavior::Tmp => {
            // Generate UID locally to avoid RTT latency
            let project_name = project_dir
                .file_name()
                .expect("Project dir should always exist");
            let uid = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let temp_path = format!("/tmp/crunch-{project_name}-{uid}");
            info!("Using temporary directory: {}", temp_path);
            temp_path
        }
        RemotePathBehavior::Unique => {
            let project_name = project_dir
                .file_name()
                .expect("Project dir should always exist");
            let uid = uid_from_path(&project_dir);
            let unique_path = format!("{}/{}-{}", remote.crunch_dir, project_name, uid);

            debug!("Using unique persistent directory: {}", unique_path);
            unique_path
        }
        RemotePathBehavior::Mirror => project_dir.to_string(),
    };

    info!("Transferring sources to remote: {}", build_path);
    let mut rsync_to = Command::new("rsync");
    rsync_to
        .arg("-a")
        .arg("--delete")
        .arg("--compress")
        .arg("-e")
        .arg(format!("ssh -p {}", remote.ssh_port))
        .arg("--info=progress2")
        .arg("--exclude")
        .arg("target");

    args.exclude.iter().for_each(|exclude| {
        rsync_to.arg("--exclude").arg(exclude);
    });


    debug!("Project directory: {}", project_dir);
    debug!("Build server: {}", build_server);
    debug!("Build path: {}", build_path);
    debug!("Remote SSH port: {}", remote.ssh_port);

    info!("Transferring sources to remote: {}", build_path);
    
    // Test SSH connectivity first
    debug!("Testing SSH connection to {}...", build_server);
    let ssh_test = Command::new("ssh")
        .args(["-p", &remote.ssh_port.to_string()])
        .arg("-o")
        .arg("ConnectTimeout=5")
        .arg(&build_server)
        .arg("echo 'SSH connection successful'")
        .output();
    
    match ssh_test {
        Ok(output) if output.status.success() => {
            debug!("SSH connection test passed");
        }
        Ok(output) => {
            error!("SSH connection failed with exit code: {}", output.status);
            error!("stderr: {}", String::from_utf8_lossy(&output.stderr));
            eprintln!("\nHint: Make sure you can connect with: ssh -p {} {}", remote.ssh_port, build_server);
            exit(-3);
        }
        Err(e) => {
            error!("Failed to execute SSH command: {}", e);
            eprintln!("\nHint: Make sure 'ssh' is installed and in your PATH");
            exit(-3);
        }
    }

    let rsync_path_arg = format!("mkdir -p {build_path} && rsync");

    rsync_to
        .arg("--rsync-path")
        .arg(rsync_path_arg)
        .arg(format!("{project_dir}/"))
        .arg(format!("{build_server}:{build_path}"))
        .env("LC_ALL", "C.UTF-8")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdin(Stdio::inherit())
        .output()
        .unwrap_or_else(|e| {
            error!("Failed to transfer project to build server (error: {})", e);
            exit(-4);
        });

    let build_command = format!(
        "export CC=gcc; export CXX=g++; source {}; cd {}; {} cargo {}",
        remote.env,
        build_path,
        args.build_env,
        args.command.join(" "),
    );

    // Add the post_cargo command to the build_command, if it exists
    let command = if let Some(post_cargo) = args.post_cargo {
        format!(
            "{build_command} && echo Executing post-cargo command && {post_cargo}"
        )
    } else {
        build_command
    };
    Command::new("ssh")
        .env("LC_ALL", "C.UTF-8")
        .args(["-p", &remote.ssh_port.to_string()])
        .arg("-t")
        .arg(&build_server)
        .arg(command)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdin(Stdio::inherit())
        .output()
        .unwrap_or_else(|e| {
            error!("Failed to run cargo command remotely (error: {})", e);
            exit(-5);
        });

    if !copy_back_pairs.is_empty() {
        info!("Transferring artifacts back to the local machine.");

        let errors = Arc::new(Mutex::new(Vec::new()));
        let threads: Vec<_> = copy_back_pairs
            .into_iter()
            .map(|(remote_source, local_dest)| {
                let errors = Arc::clone(&errors);
                let build_server = build_server.clone();
                let build_path = build_path.clone();
                thread::spawn(move || {
                    let mut rsync_back = Command::new("rsync");
                    rsync_back
                        .arg("-a")
                        .arg("--compress")
                        .arg("-e")
                        .arg(format!("ssh -p {}", remote.ssh_port))
                        .arg("--info=progress2")
                        .arg(format!(
                            "{}:{}/{}",
                            &build_server, build_path, remote_source
                        ))
                        .arg(format!("{local_dest}/"))
                        .env("LC_ALL", "C.UTF-8")
                        .stdout(Stdio::inherit())
                        .stderr(Stdio::inherit())
                        .stdin(Stdio::inherit());

                    let output = rsync_back.output();

                    match output {
                        Ok(result) if result.status.success() => {
                            info!(
                                "Successfully transferred '{}' to '{}'",
                                remote_source, local_dest
                            );
                        }
                        Ok(result) => {
                            let message = format!(
                                "Rsync failed for '{}' to '{}' with exit code: {}",
                                remote_source, local_dest, result.status
                            );
                            error!("{}", message);
                            errors.lock().unwrap().push(message);
                        }
                        Err(e) => {
                            let message = format!(
                                "Failed to transfer '{remote_source}' to '{local_dest}' (error: {e})"
                            );
                            error!("{}", message);
                            errors.lock().unwrap().push(message);
                        }
                    }
                })
            })
            .collect();

        for thread in threads {
            thread.join().unwrap();
        }

        let errors = errors.lock().unwrap();
        if !errors.is_empty() {
            for error in errors.iter() {
                eprintln!("{error}");
            }
            exit(-6);
        }
    }

    // Clean up temporary directory if we created one
    if matches!(args.remote_path, RemotePathBehavior::Tmp) {
        info!("Cleaning up temporary directory on remote server...");

        let cleanup_result = Command::new("ssh")
            .args(["-p", &remote.ssh_port.to_string()])
            .arg(&build_server)
            .arg(format!(
                "cd '{build_path}' && cargo clean && rm -r '{build_path}'"
            ))
            .output();

        match cleanup_result {
            Ok(output) if output.status.success() => {
                debug!(
                    "Successfully cleaned up temporary directory: {}",
                    build_path
                );
            }
            Ok(output) => {
                debug!(
                    "Warning: Failed to clean up temporary directory '{}': {}",
                    build_path,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(e) => {
                debug!("Warning: Could not run cleanup command (error: {})", e);
            }
        }
    }
}

fn extract_manifest_path(args: &[String]) -> Option<String> {
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--manifest-path" {
            return args.next().cloned();
        } else if arg.starts_with("--manifest-path=") {
            return Some(arg.split_once('=').unwrap().1.to_string());
        }
    }
    None
}

#[test]
fn extract_manifest_path_works() {
    // Test next arg
    let args = vec![
        "build".to_string(),
        "--release".to_string(),
        "--manifest-path".to_string(),
        "Cargo.toml".to_string(),
    ];
    assert_eq!(extract_manifest_path(&args), Some("Cargo.toml".to_string()));

    // Test equals
    let args = vec![
        "build".to_string(),
        "--release".to_string(),
        "--manifest-path=Cargo.toml".to_string(),
    ];
    assert_eq!(extract_manifest_path(&args), Some("Cargo.toml".to_string()));

    // Test none
    let args = vec!["build".to_string(), "--release".to_string()];
    assert_eq!(extract_manifest_path(&args), None);
}


// Helper function to parse remote_path string into enum
fn parse_remote_path_behavior(s: &str) -> RemotePathBehavior {
    match s.to_lowercase().as_str() {
        "mirror" => RemotePathBehavior::Mirror,
        "tmp" => RemotePathBehavior::Tmp,
        "unique" => RemotePathBehavior::Unique,
        _ => {
            eprintln!("Warning: Unknown remote_path value '{}', using 'mirror'", s);
            RemotePathBehavior::Mirror
        }
    }
}

// Add this helper trait for RemotePathBehavior
impl RemotePathBehavior {
    fn matches_default(&self) -> bool {
        matches!(self, RemotePathBehavior::Mirror)
    }
}
