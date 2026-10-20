//! Kutup's load generator (docs/research, the load-test note): virtual users
//! through the real client code (OPAQUE, Drive's file encryption and tus,
//! Chat core's engine with sealed sending and its WebSocket, Mail's OpenPGP)
//! against a test stack, with latency percentiles, error rates and
//! throughput per operation.
//!
//! Never point it at a production server: it signs up as many accounts as
//! it runs users, and the stack needs `APP_ENV=test` with
//! `RATE_LIMITS_RELAXED=true` anyway.

mod account;
mod api;
mod chat;
mod drive;
mod mail;
mod metrics;
mod scenario;
mod transport;
mod user;

use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;

use crate::metrics::Metrics;
use crate::scenario::Scenario;
use crate::user::{Directory, Run};

#[derive(Parser)]
#[command(about = "Drive virtual Kutup users against a test stack")]
struct Args {
    /// The backend, e.g. http://127.0.0.1:3000 (not a production server).
    #[arg(long, env = "KUTUP_LOAD_SERVER")]
    server: String,
    /// The scenario (TOML); defaults when left out.
    #[arg(long)]
    scenario: Option<PathBuf>,
    /// Override the scenario's user count.
    #[arg(long)]
    users: Option<usize>,
    /// Override the scenario's idle socket count.
    #[arg(long)]
    idle_sockets: Option<usize>,
    /// Override the run's length after the ramp (seconds).
    #[arg(long)]
    duration: Option<u64>,
    /// Write the final report as JSON here.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 120)]
    timeout: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut scenario = Scenario::load(args.scenario.as_deref())?;
    if let Some(users) = args.users {
        scenario.users = users;
    }
    if let Some(idle) = args.idle_sockets {
        scenario.idle_sockets = idle;
    }
    if let Some(duration) = args.duration {
        scenario.duration_secs = duration;
    }
    let base = args.server.trim_end_matches('/').to_owned();
    if base.contains("kutup.dev") {
        bail!("refusing to load-test kutup.dev");
    }

    let control = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let http = api::client(Duration::from_secs(args.timeout))?;
    let api = api::Api { http, base };
    let settings = control
        .block_on(api.settings())
        .context("the server's settings")?;
    let server_name = settings["chat"]["serverName"]
        .as_str()
        .context("the server names its accounts' domain")?
        .to_owned();
    if server_name == "kutup.dev" {
        bail!("refusing to load-test kutup.dev");
    }
    let sealed_sender = settings["chat"]["sealedSender"].as_bool().unwrap_or(false);

    let metrics = Metrics::default();
    let directory = Directory::default();
    let started = Instant::now();
    let arrivals = Duration::from_secs(scenario.ramp_secs.max(scenario.idle_ramp_secs));
    let ends_at = started + arrivals + Duration::from_secs(scenario.duration_secs);
    let tag = format!(
        "lt{}x",
        uuid::Uuid::new_v4().simple().to_string()[..6].to_owned()
    );
    eprintln!(
        "load test: {} users, {} idle sockets, ramp {}s, then {}s against {} (sealed sending {})",
        scenario.users,
        scenario.idle_sockets,
        scenario.ramp_secs,
        scenario.duration_secs,
        api.base,
        if sealed_sender { "on" } else { "off" }
    );

    let mut threads = Vec::new();
    for thread in 0..scenario.chat_threads {
        let run = Run {
            api: api.clone(),
            server_name: server_name.clone(),
            sealed_sender,
            scenario: scenario.clone(),
            metrics: metrics.clone(),
            directory: directory.clone(),
            ends_at,
            tag: tag.clone(),
        };
        threads.push(
            std::thread::Builder::new()
                .name(format!("load-{thread}"))
                .spawn(move || run_thread(run, thread))?,
        );
    }

    // Reports while the run goes on.
    let report_every = Duration::from_secs(scenario.report_every_secs.max(1));
    control.block_on(async {
        let mut last = Instant::now();
        while Instant::now() < ends_at {
            tokio::time::sleep(report_every.min(ends_at - Instant::now())).await;
            let interval = metrics.interval(last.elapsed());
            last = Instant::now();
            eprintln!(
                "--- {:>5}s, {} sockets open ---\n{}",
                started.elapsed().as_secs(),
                metrics.open_sockets(),
                metrics::table(&interval)
            );
        }
    });
    for thread in threads {
        let _ = thread.join();
    }
    let report = metrics.report(started.elapsed());
    println!("{}", metrics::table(&report));
    if let Some(out) = args.out {
        let json = serde_json::json!({
            "server": api.base,
            "scenario": format!("{scenario:?}"),
            "seconds": started.elapsed().as_secs(),
            "operations": report,
        });
        std::fs::write(&out, serde_json::to_vec_pretty(&json)?)?;
    }
    Ok(())
}

/// One Chat thread: its share of the users on one `LocalSet`.
fn run_thread(run: Run, thread: usize) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("load thread {thread}: {error}");
            return;
        }
    };
    let threads = run.scenario.chat_threads;
    let scenario = run.scenario.clone();
    let run = Rc::new(run);
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async move {
        let mut tasks = Vec::new();
        let spacing =
            |count: usize, over: u64| Duration::from_secs_f64(over as f64 / count.max(1) as f64);
        let gap = spacing(scenario.users, scenario.ramp_secs);
        for index in (thread..scenario.users).step_by(threads) {
            tasks.push(tokio::task::spawn_local(user::active(
                run.clone(),
                index,
                gap * index as u32,
            )));
        }
        let gap = spacing(scenario.idle_sockets, scenario.idle_ramp_secs);
        for index in (thread..scenario.idle_sockets).step_by(threads) {
            tasks.push(tokio::task::spawn_local(user::idle(
                run.clone(),
                index,
                gap * index as u32,
            )));
        }
        for task in tasks {
            let _ = task.await;
        }
    });
}
