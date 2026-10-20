//! One virtual user: signs up and in, sets up Drive, Mail and Chat as the
//! apps do on first use, pairs with a partner, then does the scenario's mix
//! at Poisson-random times until the run ends. Runs on a Chat thread's
//! `LocalSet`: Chat core's engine is single-threaded.

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use kutup_chat_proto::ReceiptState;
use rand::Rng as _;
use tokio::sync::Notify;
use tokio::time::sleep_until;

use crate::account::{self, User};
use crate::api::Api;
use crate::chat::{self, Chat};
use crate::drive::{self, Uploaded};
use crate::mail::{self, Address};
use crate::metrics::Metrics;
use crate::scenario::Scenario;

/// What a user's partner needs to know of them.
#[derive(Clone)]
pub struct Card {
    pub chat_account: String,
    pub mail_address: String,
    pub mail_public_key: Vec<u8>,
}

/// Every user's card, by index: partners find each other here.
#[derive(Clone, Default)]
pub struct Directory {
    cards: Arc<Mutex<HashMap<usize, Card>>>,
}

impl Directory {
    pub fn put(&self, index: usize, card: Card) {
        self.cards.lock().expect("directory").insert(index, card);
    }

    /// Waits for `index`'s card, up to `patience`.
    pub async fn wait(&self, index: usize, patience: Duration) -> Option<Card> {
        let until = Instant::now() + patience;
        loop {
            if let Some(card) = self.cards.lock().expect("directory").get(&index).cloned() {
                return Some(card);
            }
            if Instant::now() > until {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

/// What every user on a thread shares.
pub struct Run {
    pub api: Api,
    pub server_name: String,
    pub sealed_sender: bool,
    pub scenario: Scenario,
    pub metrics: Metrics,
    pub directory: Directory,
    /// When the mix stops, for everyone.
    pub ends_at: Instant,
    /// A prefix for this run's usernames, so runs never collide.
    pub tag: String,
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Refresh,
    SignIn,
    DriveUpload,
    DriveDownload,
    DriveList,
    ChatText,
    ChatTyping,
    MailSend,
    MailList,
    MailOpen,
}

impl Op {
    const ALL: [Op; 10] = [
        Op::Refresh,
        Op::SignIn,
        Op::DriveUpload,
        Op::DriveDownload,
        Op::DriveList,
        Op::ChatText,
        Op::ChatTyping,
        Op::MailSend,
        Op::MailList,
        Op::MailOpen,
    ];

    fn per_minute(self, scenario: &Scenario) -> f64 {
        let mix = &scenario.mix;
        match self {
            Op::Refresh => mix.refresh,
            Op::SignIn => mix.sign_in,
            Op::DriveUpload => mix.drive_upload,
            Op::DriveDownload => mix.drive_download,
            Op::DriveList => mix.drive_list,
            Op::ChatText => mix.chat_text,
            Op::ChatTyping => mix.chat_typing,
            Op::MailSend => mix.mail_send,
            Op::MailList => mix.mail_list,
            Op::MailOpen => mix.mail_open,
        }
    }
}

/// The next time an event with `per_minute` happens: an exponential gap.
fn next_at(per_minute: f64) -> Option<Instant> {
    if per_minute <= 0.0 {
        return None;
    }
    let uniform: f64 = rand::rng().random_range(f64::EPSILON..1.0);
    let seconds = -uniform.ln() * 60.0 / per_minute;
    Some(Instant::now() + Duration::from_secs_f64(seconds))
}

fn size(scenario: &Scenario) -> usize {
    let total: u32 = scenario.drive.weights.iter().sum();
    let mut pick = rand::rng().random_range(0..total.max(1));
    for (kib, weight) in scenario.drive.sizes_kib.iter().zip(&scenario.drive.weights) {
        if pick < *weight {
            return (*kib as usize) * 1024;
        }
        pick -= weight;
    }
    1024
}

/// The partner of user `index`: its neighbour in the pair.
fn partner_of(index: usize, users: usize) -> Option<usize> {
    let partner = index ^ 1;
    (partner < users).then_some(partner)
}

/// A whole active user, from sign-up to the end of the run.
pub async fn active(run: Rc<Run>, index: usize, start_after: Duration) {
    tokio::time::sleep(start_after).await;
    if let Err(error) = active_inner(&run, index).await {
        run.metrics
            .error("user.failed", crate::metrics::kind(&error));
    }
}

async fn active_inner(run: &Run, index: usize) -> Result<()> {
    let metrics = &run.metrics;
    let api = &run.api;
    let username = format!("{}{index}", run.tag);
    let mut user = metrics
        .time(
            "sign_up",
            account::sign_up(api, &run.server_name, &username),
        )
        .await?;
    metrics
        .time("sign_in", account::sign_in(api, &mut user))
        .await?;
    let folder = metrics
        .time("drive.folder", drive::create_folder(api, &user))
        .await?;
    let address = metrics
        .time("mail.setup", mail::set_up_address(api, &user))
        .await?;
    let mut chat = metrics
        .time("chat.open", Chat::open(api, &user, run.sealed_sender))
        .await?;
    run.directory.put(
        index,
        Card {
            chat_account: user.chat_account(),
            mail_address: address.address.clone(),
            mail_public_key: address.public_key.clone(),
        },
    );
    let partner = match partner_of(index, run.scenario.users) {
        Some(partner) => {
            run.directory
                .wait(partner, Duration::from_secs(run.scenario.ramp_secs + 600))
                .await
        }
        None => None,
    };
    // As two people start: one writes first (a message request), the other
    // reads it and accepts.
    if let Some(partner) = &partner {
        if index.is_multiple_of(2) {
            metrics
                .time("chat.text", chat.send_text(&partner.chat_account))
                .await?;
        } else {
            metrics
                .time(
                    "chat.request_arrived",
                    wait_for_request(&mut chat, &partner.chat_account),
                )
                .await?;
            metrics
                .time("chat.accept", chat.accept(&partner.chat_account))
                .await?;
        }
    }

    let arrived = Rc::new(Notify::new());
    let stop = Rc::new(Notify::new());
    let socket = tokio::task::spawn_local(chat::hold_socket(
        api.clone(),
        user.token.clone(),
        chat.device_id(),
        arrived.clone(),
        stop.clone(),
        metrics.clone(),
    ));

    let mut user_state = State {
        user,
        folder,
        address,
        partner,
        uploaded: Vec::new(),
    };
    let mut due: Vec<(Option<Instant>, Op)> = Op::ALL
        .iter()
        .map(|op| (next_at(op.per_minute(&run.scenario)), *op))
        .collect();
    let ends_at = tokio::time::Instant::from_std(run.ends_at);
    while let Some((slot, at)) = due
        .iter()
        .enumerate()
        .filter_map(|(i, (at, _))| at.map(|at| (i, at)))
        .min_by_key(|(_, at)| *at)
    {
        tokio::select! {
            _ = sleep_until(ends_at) => break,
            _ = arrived.notified() => {
                read_mailbox(run, &mut chat, &user_state).await;
            }
            _ = sleep_until(tokio::time::Instant::from_std(at)) => {
                let op = due[slot].1;
                due[slot].0 = next_at(op.per_minute(&run.scenario));
                let _ = do_op(run, op, &mut chat, &mut user_state).await;
            }
        }
    }
    stop.notify_one();
    let _ = socket.await;
    Ok(())
}

/// Reads the mailbox until `peer`'s first message is there.
async fn wait_for_request(chat: &mut Chat, peer: &str) -> Result<()> {
    let until = Instant::now() + Duration::from_secs(300);
    while Instant::now() < until {
        let messages = chat.reconcile().await?;
        if messages.iter().any(|m| m.from.account.to_string() == peer) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(anyhow!("the partner's first message never came"))
}

struct State {
    user: User,
    folder: drive::Folder,
    address: Address,
    partner: Option<Card>,
    uploaded: Vec<Uploaded>,
}

/// Reads the mailbox after the socket's nudge, times each load-test text
/// from its send, and answers it with delivery and read receipts.
async fn read_mailbox(run: &Run, chat: &mut Chat, state: &State) {
    let Ok(messages) = run.metrics.time("chat.reconcile", chat.reconcile()).await else {
        return;
    };
    let mut texts = Vec::new();
    for message in &messages {
        if let Some(ms) = chat::delivery_ms(message) {
            run.metrics
                .ok("chat.delivered_e2e", Duration::from_millis(ms));
            texts.push(message.content.message_id.clone());
        }
    }
    let Some(partner) = &state.partner else {
        return;
    };
    if texts.is_empty() {
        return;
    }
    for receipt in [ReceiptState::Delivered, ReceiptState::Read] {
        let _ = run
            .metrics
            .time(
                "chat.receipt",
                chat.send_receipt(&partner.chat_account, texts.clone(), receipt),
            )
            .await;
    }
}

async fn do_op(run: &Run, op: Op, chat: &mut Chat, state: &mut State) -> Result<()> {
    let metrics = &run.metrics;
    let api = &run.api;
    match op {
        Op::Refresh => {
            metrics
                .time("refresh", account::refresh(api, &mut state.user))
                .await?;
            *chat.token.borrow_mut() = state.user.token.clone();
        }
        Op::SignIn => {
            metrics
                .time("sign_in", account::sign_in(api, &mut state.user))
                .await?;
            *chat.token.borrow_mut() = state.user.token.clone();
        }
        Op::DriveUpload => {
            let size = size(&run.scenario);
            let uploaded = metrics
                .time(
                    size_label(size),
                    drive::upload(api, &state.user, &state.folder, size),
                )
                .await?;
            state.uploaded.push(uploaded);
        }
        Op::DriveDownload => {
            let Some(file) = state.uploaded.last() else {
                return Ok(());
            };
            metrics
                .time("drive.download", drive::download(api, &state.user, file))
                .await?;
        }
        Op::DriveList => {
            metrics
                .time("drive.list", drive::list(api, &state.user, &state.folder))
                .await?;
        }
        Op::ChatText => {
            let Some(partner) = &state.partner else {
                return Ok(());
            };
            metrics
                .time("chat.text", chat.send_text(&partner.chat_account))
                .await?;
        }
        Op::ChatTyping => {
            let Some(partner) = &state.partner else {
                return Ok(());
            };
            metrics
                .time("chat.typing", chat.send_typing(&partner.chat_account))
                .await?;
        }
        Op::MailSend => {
            let Some(partner) = &state.partner else {
                return Ok(());
            };
            let to = Address {
                address: partner.mail_address.clone(),
                secret_key: Vec::new(),
                public_key: partner.mail_public_key.clone(),
            };
            metrics
                .time(
                    "mail.send",
                    mail::send(api, &state.user, &state.address, &to),
                )
                .await?;
        }
        Op::MailList => {
            metrics
                .time("mail.list", mail::list(api, &state.user))
                .await?;
        }
        Op::MailOpen => {
            let rows = mail::list(api, &state.user).await?;
            let Some(id) = rows.first().and_then(|row| row["id"].as_str()) else {
                return Ok(());
            };
            metrics
                .time(
                    "mail.open",
                    mail::open(api, &state.user, &state.address, id),
                )
                .await?;
        }
    }
    Ok(())
}

fn size_label(size: usize) -> &'static str {
    match size / 1024 {
        0..=64 => "drive.upload.small",
        65..=1024 => "drive.upload.medium",
        1025..=8192 => "drive.upload.large",
        _ => "drive.upload.huge",
    }
}

/// A signed-in user that only holds its Chat socket open, to find how many
/// connections the server keeps.
pub async fn idle(run: Rc<Run>, index: usize, start_after: Duration) {
    tokio::time::sleep(start_after).await;
    let result: Result<()> = async {
        let username = format!("{}i{index}", run.tag);
        let user = run
            .metrics
            .time(
                "idle.sign_up",
                account::sign_up(&run.api, &run.server_name, &username),
            )
            .await?;
        let chat = run
            .metrics
            .time(
                "idle.chat_open",
                Chat::open(&run.api, &user, run.sealed_sender),
            )
            .await?;
        let arrived = Rc::new(Notify::new());
        let stop = Rc::new(Notify::new());
        let stopper = stop.clone();
        let ends_at = tokio::time::Instant::from_std(run.ends_at);
        tokio::task::spawn_local(async move {
            sleep_until(ends_at).await;
            stopper.notify_one();
        });
        chat::hold_socket(
            run.api.clone(),
            user.token.clone(),
            chat.device_id(),
            arrived,
            stop,
            run.metrics.clone(),
        )
        .await
        .map_err(|e| anyhow!(e))
    }
    .await;
    if let Err(error) = result {
        run.metrics
            .error("idle.failed", crate::metrics::kind(&error));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairs_are_neighbours_and_a_last_odd_user_has_none() {
        assert_eq!(partner_of(0, 4), Some(1));
        assert_eq!(partner_of(1, 4), Some(0));
        assert_eq!(partner_of(3, 4), Some(2));
        assert_eq!(partner_of(4, 5), None);
    }

    #[test]
    fn a_rate_of_zero_never_happens_and_gaps_average_out() {
        assert!(next_at(0.0).is_none());
        let start = Instant::now();
        let mean = (0..20_000)
            .map(|_| next_at(60.0).unwrap().duration_since(start).as_secs_f64())
            .sum::<f64>()
            / 20_000.0;
        // 60 a minute: a second apart on average.
        assert!((0.9..1.1).contains(&mean), "{mean}");
    }

    #[test]
    fn sizes_follow_the_weights() {
        let mut scenario = Scenario::default();
        scenario.drive.sizes_kib = vec![1, 2];
        scenario.drive.weights = vec![0, 1];
        assert!((0..100).all(|_| size(&scenario) == 2048));
    }
}
