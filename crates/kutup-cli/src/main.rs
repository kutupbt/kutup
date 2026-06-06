//! kutup CLI — Rust rewrite of `cmd/kutup`. E2E-encrypted file storage client.
//!
//! Commands are ported incrementally; only fully-wired commands are exposed
//! (no stubs). See `docs/roadmap.md` / the rewrite branch for what remains.

// TODO(rust-rewrite): drop once the command surface (mkdir/mv/rm/sync/share/…)
// consumes the remaining API + session methods already ported below.
#![allow(dead_code)]

mod api;
mod commands;
mod config;
mod context;
mod cryptohelpers;
mod output;
mod session;
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
    /// Authenticate and store session.
    Login {
        /// Server URL (e.g. https://kutup.example.com).
        #[arg(long)]
        server: Option<String>,
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
}

fn main() {
    let cli = Cli::parse();
    let result = match &cli.command {
        Commands::Login { server } => commands::login::run(&cli.profile, server.as_deref()),
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
    };
    if let Err(e) = result {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
