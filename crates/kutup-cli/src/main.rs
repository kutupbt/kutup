//! kutup CLI — Rust rewrite of `cmd/kutup`. E2E-encrypted file storage client.
//!
//! Commands are ported incrementally; only fully-wired commands are exposed
//! (no stubs). See `docs/roadmap.md` / the rewrite branch for what remains.

mod api;
mod commands;
mod config;
mod context;
mod cryptohelpers;
mod errors;
mod mimetype;
mod output;
mod session;
mod syncengine;
mod transfer;
mod uploader;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "kutup",
    about = "Kutup CLI — E2E encrypted file storage",
    version,
    disable_help_subcommand = true
)]
struct Cli {
    /// Profile name (for multiple accounts).
    #[arg(long, global = true, default_value = "default")]
    profile: String,
    /// Output as JSON.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new account (generates keys client-side; prints a recovery phrase).
    Register {
        /// Server URL (e.g. https://kutup.example.com).
        #[arg(long)]
        server: Option<String>,
        /// Email for the new account.
        #[arg(long)]
        email: Option<String>,
        /// Username (3-32 chars: lowercase letters, numbers, _ and -).
        #[arg(long)]
        username: Option<String>,
    },
    /// Authenticate and store session.
    Login {
        /// Server URL (e.g. https://kutup.example.com).
        #[arg(long)]
        server: Option<String>,
        /// Email (for non-interactive login; password via KUTUP_PASSWORD env).
        #[arg(long)]
        email: Option<String>,
    },
    /// Reset your password with the 24-word recovery phrase, then log in.
    Recover {
        /// Server URL (e.g. https://kutup.example.com).
        #[arg(long)]
        server: Option<String>,
        /// Email (non-interactive: KUTUP_RECOVERY_PHRASE + KUTUP_PASSWORD env).
        #[arg(long)]
        email: Option<String>,
    },
    /// Clear stored session.
    Logout,
    /// Show current user info.
    Whoami,
    /// List files and folders.
    Ls {
        /// Show the full folder tree.
        #[arg(long)]
        tree: bool,
        /// Folder id to list (omit for top level).
        folder_id: Option<String>,
    },
    /// Create a new folder.
    Mkdir {
        /// Folder name.
        name: String,
        /// Parent folder id (for a nested folder).
        #[arg(long)]
        parent: Option<String>,
    },
    /// Rename a file or folder (re-encrypts the name; content untouched).
    Mv {
        /// File or folder id.
        id: String,
        /// New name.
        new_name: String,
        /// Rename a folder (collection) instead of a file.
        #[arg(long)]
        folder: bool,
    },
    /// Move a file or folder to the trash.
    Rm {
        /// File or folder id.
        id: String,
        /// Delete a folder (collection) instead of a file.
        #[arg(long)]
        folder: bool,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// Encrypt and upload a file or directory (interrupted uploads resume).
    Upload {
        /// Local file or directory path.
        path: String,
        /// Destination collection id.
        collection_id: String,
        /// Upload a directory recursively.
        #[arg(short, long)]
        recursive: bool,
        /// Discard any interrupted prior attempt and restart from zero.
        #[arg(long)]
        no_resume: bool,
    },
    /// Download and decrypt a file.
    Download {
        /// File id.
        file_id: String,
        /// Destination directory or path (default: current directory).
        dest: Option<String>,
    },
    /// Bidirectional sync between a local directory and a remote collection.
    Sync {
        /// Local directory.
        local_dir: String,
        /// Remote collection id.
        collection_id: String,
        /// Stay running and sync on file changes.
        #[arg(long)]
        watch: bool,
    },
    /// Set the display color for a collection (e.g. #ef4444; "" to clear).
    Color {
        /// Collection id.
        collection_id: String,
        /// Hex color #rrggbb, or "" to clear.
        hex: String,
    },
    /// List, restore, and permanently delete trashed items.
    Trash {
        #[command(subcommand)]
        command: commands::trash::TrashCmd,
    },
    /// Manage TOTP two-factor authentication.
    #[command(name = "2fa")]
    Twofa {
        #[command(subcommand)]
        command: commands::twofa::TwofaCmd,
    },
    /// List and revoke devices on your account.
    Devices {
        #[command(subcommand)]
        command: commands::devices::DevicesCmd,
    },
    /// List, download, restore, and label snapshot versions of a file.
    Versions {
        #[command(subcommand)]
        command: commands::versions::VersionsCmd,
    },
    /// Share folders (with users, federated servers, or public links).
    Share {
        #[command(subcommand)]
        command: commands::share::ShareCmd,
    },
    /// Consume a public share link (no login required for the link).
    Pub {
        #[command(subcommand)]
        command: commands::pubshare::PubCmd,
    },
    /// Print the kutup CLI version + build info.
    Version,
}

fn main() {
    let cli = Cli::parse();
    let result = match &cli.command {
        Commands::Register {
            server,
            email,
            username,
        } => commands::register::run(
            cli.json,
            server.as_deref(),
            email.as_deref(),
            username.as_deref(),
        ),
        Commands::Login { server, email } => {
            commands::login::run(&cli.profile, cli.json, server.as_deref(), email.as_deref())
        }
        Commands::Recover { server, email } => {
            commands::recover::run(&cli.profile, cli.json, server.as_deref(), email.as_deref())
        }
        Commands::Logout => commands::logout::run(&cli.profile, cli.json),
        Commands::Whoami => commands::whoami::run(&cli.profile, cli.json),
        Commands::Ls { tree, folder_id } => {
            commands::ls::run(&cli.profile, cli.json, *tree, folder_id.as_deref())
        }
        Commands::Mkdir { name, parent } => {
            commands::mkdir::run(&cli.profile, cli.json, name, parent.as_deref())
        }
        Commands::Mv {
            id,
            new_name,
            folder,
        } => commands::mv::run(&cli.profile, cli.json, id, new_name, *folder),
        Commands::Rm { id, folder, yes } => {
            commands::rm::run(&cli.profile, cli.json, id, *folder, *yes)
        }
        Commands::Upload {
            path,
            collection_id,
            recursive,
            no_resume,
        } => commands::upload::run(
            &cli.profile,
            cli.json,
            path,
            collection_id,
            *recursive,
            *no_resume,
        ),
        Commands::Download { file_id, dest } => {
            commands::download::run(&cli.profile, cli.json, file_id, dest.as_deref())
        }
        Commands::Sync {
            local_dir,
            collection_id,
            watch,
        } => commands::sync::run(&cli.profile, cli.json, local_dir, collection_id, *watch),
        Commands::Color { collection_id, hex } => {
            commands::color::run(&cli.profile, cli.json, collection_id, hex)
        }
        Commands::Trash { command } => commands::trash::run(&cli.profile, cli.json, command),
        Commands::Twofa { command } => commands::twofa::run(&cli.profile, cli.json, command),
        Commands::Devices { command } => commands::devices::run(&cli.profile, cli.json, command),
        Commands::Versions { command } => commands::versions::run(&cli.profile, cli.json, command),
        Commands::Share { command } => commands::share::run(&cli.profile, cli.json, command),
        Commands::Pub { command } => commands::pubshare::run(cli.json, command),
        Commands::Version => commands::version::run(cli.json),
    };
    if let Err(e) = result {
        let code = exit_code_for(&e);
        if cli.json {
            // Keep stderr machine-readable too when the caller asked for JSON.
            let mut obj = serde_json::json!({
                "error": format!("{e:#}"),
                "exitCode": code,
            });
            if let Some(api) = e.downcast_ref::<api::ApiError>() {
                obj["httpStatus"] = api.status.into();
            }
            eprintln!("{obj}");
        } else {
            eprintln!("{} {e:#}", output::error_prefix());
        }
        std::process::exit(code);
    }
}

/// Maps an error chain to a process exit code: 0 ok · 1 generic · 2 usage
/// (matches clap's parse-error code) · 3 auth/session · 4 not found ·
/// 5 network/server. Downcasting sees through `.context()` layers.
fn exit_code_for(err: &anyhow::Error) -> i32 {
    if err.downcast_ref::<errors::UsageError>().is_some() {
        return 2;
    }
    if err.downcast_ref::<errors::NotLoggedIn>().is_some() {
        return 3;
    }
    if err.downcast_ref::<errors::NotFound>().is_some() {
        return 4;
    }
    if let Some(api) = err.downcast_ref::<api::ApiError>() {
        return match api.status {
            401 | 403 => 3,
            404 => 4,
            408 | 429 => 5,
            s if s >= 500 => 5,
            _ => 1,
        };
    }
    if let Some(re) = err.downcast_ref::<reqwest::Error>() {
        if re.is_connect() || re.is_timeout() || re.is_request() {
            return 5;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[test]
    fn exit_codes_map_marker_errors_through_context() {
        let e = anyhow::Error::new(errors::NotLoggedIn("not logged in".into()))
            .context("load session")
            .context("whoami");
        assert_eq!(exit_code_for(&e), 3);

        let e = anyhow::Error::new(errors::NotFound("file x not found".into())).context("download");
        assert_eq!(exit_code_for(&e), 4);

        let e = anyhow::Error::new(errors::UsageError("pass --yes".into()));
        assert_eq!(exit_code_for(&e), 2);
    }

    #[test]
    fn exit_codes_map_api_errors_by_status() {
        let cases = [
            (401, 3),
            (403, 3),
            (404, 4),
            (408, 5),
            (429, 5),
            (500, 5),
            (503, 5),
            (409, 1),
            (413, 1),
        ];
        for (status, want) in cases {
            let e = anyhow::Error::new(api::ApiError {
                status,
                message: "x".into(),
            })
            .context("outer")
            .context("outermost");
            assert_eq!(exit_code_for(&e), want, "status {status}");
        }
    }

    #[test]
    fn exit_codes_default_to_one() {
        assert_eq!(exit_code_for(&anyhow!("something else")), 1);
    }
}
