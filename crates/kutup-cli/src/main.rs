//! kutup CLI — Rust rewrite of `cmd/kutup`. E2E-encrypted file storage client.
//!
//! Commands are ported incrementally; only fully-wired commands are exposed
//! (no stubs). See `docs/roadmap.md` / the rewrite branch for what remains.

mod api;
mod commands;
mod config;
mod context;
mod cryptohelpers;
mod output;
mod session;
mod syncengine;
mod transfer;

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
    /// Rename a file (re-encrypts metadata; content untouched).
    Mv {
        /// File id.
        file_id: String,
        /// New name.
        new_name: String,
    },
    /// Delete a file or folder.
    Rm {
        /// File or folder id.
        id: String,
        /// Delete a folder (collection) instead of a file.
        #[arg(long)]
        folder: bool,
    },
    /// Encrypt and upload a file or directory.
    Upload {
        /// Local file or directory path.
        path: String,
        /// Destination collection id.
        collection_id: String,
        /// Upload a directory recursively.
        #[arg(short, long)]
        recursive: bool,
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
            commands::login::run(&cli.profile, server.as_deref(), email.as_deref())
        }
        Commands::Logout => commands::logout::run(&cli.profile),
        Commands::Whoami => commands::whoami::run(&cli.profile, cli.json),
        Commands::Ls { tree, folder_id } => {
            commands::ls::run(&cli.profile, cli.json, *tree, folder_id.as_deref())
        }
        Commands::Mkdir { name, parent } => {
            commands::mkdir::run(&cli.profile, cli.json, name, parent.as_deref())
        }
        Commands::Mv { file_id, new_name } => {
            commands::mv::run(&cli.profile, cli.json, file_id, new_name)
        }
        Commands::Rm { id, folder } => commands::rm::run(&cli.profile, cli.json, id, *folder),
        Commands::Upload {
            path,
            collection_id,
            recursive,
        } => commands::upload::run(&cli.profile, cli.json, path, collection_id, *recursive),
        Commands::Download { file_id, dest } => {
            commands::download::run(&cli.profile, cli.json, file_id, dest.as_deref())
        }
        Commands::Sync {
            local_dir,
            collection_id,
            watch,
        } => commands::sync::run(&cli.profile, local_dir, collection_id, *watch),
        Commands::Color { collection_id, hex } => {
            commands::color::run(&cli.profile, cli.json, collection_id, hex)
        }
        Commands::Devices { command } => commands::devices::run(&cli.profile, cli.json, command),
        Commands::Versions { command } => commands::versions::run(&cli.profile, cli.json, command),
        Commands::Share { command } => commands::share::run(&cli.profile, cli.json, command),
        Commands::Pub { command } => commands::pubshare::run(cli.json, command),
        Commands::Version => {
            commands::version::run(cli.json);
            Ok(())
        }
    };
    if let Err(e) = result {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
