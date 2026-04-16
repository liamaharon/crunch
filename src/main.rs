//! Turbocharge your Rust workflow.
//!
//! crunch seamlessly integrates cutting-edge hardware into your local development environment.

mod config;

use crate::config::{
    ensure_config_exists, parse_copy_back_pairs, resolve_args, CliArgs, RemotePathBehavior,
};
use cargo_metadata::camino::Utf8PathBuf;
use clap::Parser;
use log::{debug, error, info};
use std::{
    hash::{DefaultHasher, Hash, Hasher},
    process::{exit, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};
use which::which;

#[derive(Debug, Clone)]
pub struct Remote {
    pub name: String,
    pub host: String,
    pub ssh_port: u16,
    pub crunch_dir: String,
    pub env: String,
}

fn uid_from_path(path: &Utf8PathBuf) -> u64 {
    let mut hasher = DefaultHasher::new();
    path.as_str().hash(&mut hasher);
    hasher.finish()
}

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    let cli_args = CliArgs::parse();
    debug!("{:?}", &cli_args);

    let manifest_path = extract_manifest_path(&cli_args.command);

    // Run it once redirecting logs to terminal to ensure if something needs to be installed, user
    // sees it.
    let mut metadata_probe = Command::new("cargo");
    metadata_probe.args(["metadata", "--no-deps", "--format-version", "1"]);
    if let Some(manifest_path) = manifest_path.as_ref() {
        metadata_probe.arg("--manifest-path").arg(manifest_path);
    }
    metadata_probe
        .stderr(Stdio::inherit())
        .output()
        .unwrap_or_else(|e| {
            error!("Failed to run cargo command remotely (error: {})", e);
            exit(-5);
        });

    // Now run it again to get the workspace_root.
    let mut metadata_cmd = cargo_metadata::MetadataCommand::new();
    metadata_cmd.no_deps();
    if let Some(manifest_path) = manifest_path.as_ref() {
        metadata_cmd.manifest_path(manifest_path);
    }
    let project_metadata = metadata_cmd.exec().unwrap();
    let project_dir = project_metadata.workspace_root;
    if ensure_config_exists(project_dir.as_ref()).unwrap_or_else(|message| {
        error!("{}", message);
        exit(-8);
    }) {
        println!("New crunch workspace detected, initialised crunch config.");
    }
    let args = resolve_args(cli_args, project_dir.as_ref()).unwrap_or_else(|message| {
        error!("{}", message);
        exit(-8);
    });
    debug!("{:?}", &args);
    let copy_back_pairs = parse_copy_back_pairs(&args.copy_back).unwrap_or_else(|message| {
        error!("{}", message);
        exit(-9);
    });

    let remote = Remote {
        name: "crunch".to_string(),
        host: "crunch".to_string(),
        ssh_port: 22,
        crunch_dir: "~/crunch-builds".to_string(),
        env: "~/.profile".to_string(),
    };

    let build_server = remote.host;
    let ssh_transport = if args.quiet {
        format!("ssh -p {} -o LogLevel=ERROR", remote.ssh_port)
    } else {
        format!("ssh -p {}", remote.ssh_port)
    };

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

    // check if rsync is installed / in $PATH
    which("rsync").unwrap_or_else(|e| {
        error!("rsync not found in $PATH, please install it (error: {})", e);
        exit(-7)
    });

    info!("Transferring sources to remote: {}", build_path);
    let mut rsync_to = Command::new("rsync");
    rsync_to
        .arg("-a")
        .arg("--delete")
        .arg("--compress")
        .arg("-e")
        .arg(&ssh_transport);

    if !args.quiet {
        rsync_to.arg("--info=progress2");
    }

    args.exclude.iter().for_each(|exclude| {
        rsync_to.arg("--exclude").arg(exclude);
    });

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
        format!("{build_command} && echo Executing post-cargo command && {post_cargo}")
    } else {
        build_command
    };
    let mut remote_build = Command::new("ssh");
    remote_build
        .env("LC_ALL", "C.UTF-8")
        .args(["-p", &remote.ssh_port.to_string()]);
    if args.quiet {
        remote_build.args(["-o", "LogLevel=ERROR"]);
    }
    remote_build
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
                let ssh_transport = ssh_transport.clone();
                let quiet = args.quiet;
                thread::spawn(move || {
                    let mut rsync_back = Command::new("rsync");
                    rsync_back
                        .arg("-a")
                        .arg("--compress")
                        .arg("-e")
                        .arg(&ssh_transport)
                        .arg(format!(
                            "{}:{}/{}",
                            &build_server, build_path, remote_source
                        ))
                        .arg(format!("{local_dest}/"))
                        .env("LC_ALL", "C.UTF-8")
                        .stdout(Stdio::inherit())
                        .stderr(Stdio::inherit())
                        .stdin(Stdio::inherit());

                    if !quiet {
                        rsync_back.arg("--info=progress2");
                    }

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

        let mut cleanup = Command::new("ssh");
        cleanup.args(["-p", &remote.ssh_port.to_string()]);
        if args.quiet {
            cleanup.args(["-o", "LogLevel=ERROR"]);
        }
        let cleanup_result = cleanup
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
