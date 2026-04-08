# crunch

![Crates.io Version](https://img.shields.io/crates/v/crunch-app)

`crunch` is a drop-in `cargo` replacement for offloading Rust compilation to a remote server.

Cut compile times and iterate faster!

## Usage

Just replace `cargo` with `crunch`.

```bash
c̶a̶r̶g̶o̶crunch check
c̶a̶r̶g̶o̶crunch clippy --workspace
c̶a̶r̶g̶o̶crunch t -p sys-internals
```

## Installation

```bash
cargo install crunch-app
```

## Setup

1. Install Rust on a Debian-based machine
2. Add a `crunch` host to your `~/.ssh/config`

```text
Host crunch
  HostName your-machine-ip
  User your-machine-user
  IdentityFile ~/.ssh/your-key.pem
  ControlMaster auto
  ControlPath ~/.ssh/control-%r@%h:%p
  ControlPersist 5m
```

3. Ready to use `crunch` 🔥

### What Hardware Should I Use?

I recommend prioritising fewer high performing cores over many slower cores.

As of mid-2025, I'm personally using a [`Hetzner AX102`](https://www.hetzner.com/dedicated-rootserver/ax102/), which has compile times approximately equivalent to an Apple M4 Pro chip. The AX42 and AX52 are also great options.

If there is demand, I will consider selling access to managed hardware directly in the cli. Interested? [Come say hi in Discord](https://discord.gg/pS5rvjZXzq)!

## rust-analyzer (experimental)

Use `crunch` with `rust-analyzer` by setting `rust-analyzer.check.overrideCommand` to your preferred `crunch` command, including the `--message-format=json` flag.

e.g. in VSCode, you might set

```text
  "rust-analyzer.check.overrideCommand": [
    "crunch",
    "check",
    "--quiet",
    "--workspace",
    "--message-format=json",
    "--all-targets",
    "--all-features"
  ],
```

in your `settings.json`.

## Advanced Usage

```
Usage: crunch [OPTIONS] <COMMAND>...

Arguments:
  <COMMAND>...
          The cargo command to execute

          Example: `build --release`

Options:
  -e, --build-env <BUILD_ENV>
          Set remote environment variables. RUST_BACKTRACE, CC, LIB, etc

      --exclude <EXCLUDE>
          Path or directory to exclude from the remote server transfer. Specify multiple entries using delimiter ','.

          Example: `--exclude "target,.git,cat.png,*.lock,mocks/**/*.db"`

      --post-cargo <POST_CARGO>
          A command to execute on the machine after the cargo command has finished executing.

          Example: `--post-cargo "cd target/release && profile my-binary"`

      --copy-back <COPY_BACK>
          Path or directory to sync back from the remote server after all other work has been done. Each entry should be in the format `source:destination`. Specify multiple entries using delimiter ','.

          Example: `--copy-back "./target/release/cuter-cat.png:.,*.bin:~/my-bins"`

      --remote-path <REMOTE_PATH>
          Specify the remote path behavior for builds

          Possible values:
          - mirror: Mirror the local directory structure on the remote server (default)
          - tmp:    Use a temporary directory that is cleaned up after the build
          - unique: Use a unique persistent directory in the user's home directory for each project

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version

CONFIG:
    crunch automatically creates crunch.config.toml in the Cargo workspace root on first run.
    CLI flags override config values.

EXAMPLES:
    crunch -e RUST_LOG=debug check --all-features --all-targets
    crunch test -- --nocapture
```

## Project Config

`crunch` automatically looks for `crunch.config.toml` in the Cargo workspace root and uses it for project-level defaults.

On the first `crunch` run in a workspace, `crunch` creates this file automatically and prints:

```text
New crunch workspace detected, initialised crunch config.
```

Precedence:

1. `crunch.config.toml`
2. CLI flags

For list options such as `exclude` and `copy_back`, CLI values replace the config file values.

```toml
build_env = "RUST_BACKTRACE=1"
exclude = ["target", ".git"]
post_cargo = "cd target/release && profile my-binary"
copy_back = ["./target/release/cuter-cat.png:."]
remote_path = "mirror"
```

## `cargo-remote`

`crunch` was inspired by [cargo-remote](https://github.com/sgeisler/cargo-remote), aiming to achieve the same goals but with a simpler developer experience.

- Just replace `cargo` with `crunch`
- Minimal configuration (just set a host in `~/.ssh/config`)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=liamaharon/crunch-cli&type=Date)](https://www.star-history.com/#liamaharon/crunch-cli&Date)
