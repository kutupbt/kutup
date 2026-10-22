//! Every rate limit the server keeps, in one list
//! (docs/plans/admin-rate-limits.md §1): its key, the environment variable
//! that may give its first value, its default, what it counts and per what,
//! and the admin page's section. Every limiter and database budget is built
//! from its entry here ([`super::RateLimiter::registered`],
//! [`super::value`]); a limit kept anywhere else is a review error.

use std::time::Duration;

/// What one limit counts against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum Per {
    /// A client's address (an IPv6 address by its /64).
    Address,
    Account,
    /// One account signing in from one client.
    AccountAndClient,
    /// One account asking one peer server.
    AccountAndPeer,
    Device,
    /// One sign-in waiting for its second factor.
    SignIn,
    /// A group member's pseudonym.
    Pseudonym,
    Group,
    /// A peer server.
    Peer,
    /// A peer server and one of its shares.
    PeerAndShare,
    /// A sealed-sender capability.
    Capability,
    Recipient,
    /// One mail forwarding.
    Forwarding,
    /// One open connection (a collaboration socket).
    Connection,
    /// The whole server.
    Server,
}

/// The admin page's section a limit is listed under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum Section {
    Accounts,
    Drive,
    Chat,
    Groups,
    Mail,
    Calendar,
    CallsAndMaps,
    Pass,
    Federation,
    Administration,
}

/// What a limit's value means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    /// Events in a window of this length.
    Events(Duration),
    /// Events in the sign-in lockout's window ([`Limit::LoginLockoutMinutes`]).
    EventsPerLockout,
    /// Wrong attempts before a lock.
    Attempts,
    /// A length of time, in minutes.
    Minutes,
    /// Bytes in a window of this length.
    Bytes(Duration),
    /// How many may be under way at once (or a burst allowed at once).
    AtOnce,
    /// Bytes allowed at once (a burst).
    BytesAtOnce,
}

/// One limit's entry.
pub struct Spec {
    pub limit: Limit,
    /// Its name in settings and the admin API (`rate_limit.<key>`).
    pub key: &'static str,
    /// The environment variable that may set its first value.
    pub env: Option<&'static str>,
    pub default: u64,
    pub unit: Unit,
    pub per: Per,
    pub section: Section,
    /// What it stops, for the admin page.
    pub about: &'static str,
}

/// What a test stack's limits become (`RATE_LIMITS_RELAXED`): high enough
/// that a suite signing in hundreds of times never meets them.
pub const RELAXED: u64 = 100_000;

impl Spec {
    /// Whether a test stack raises it: the `RATE_LIMIT_*` ones. The sign-in
    /// lockout keeps its defaults (tests rarely miss a password, and some
    /// check that the lockout comes); limits without a variable keep theirs.
    pub fn relaxed(&self) -> bool {
        self.env.is_some_and(|name| name.starts_with("RATE_LIMIT_"))
    }

    /// Whether it guards against guessing (a credential, a code, an
    /// account): its ceiling stays 100 times its default even where
    /// `RATE_LIMIT_*` values may go higher on test stacks.
    pub fn guards_guessing(&self) -> bool {
        matches!(
            self.limit,
            Limit::Login
                | Limit::LoginLockoutThreshold
                | Limit::LoginAccountCeiling
                | Limit::LoginAccountDailyCeiling
                | Limit::LoginSourceDailyCeiling
                | Limit::TotpAttempts
                | Limit::PassPinAttempts
                | Limit::ForwardingCodeAttempts
                | Limit::Register
                | Limit::RegistrationCodeChecks
                | Limit::RegistrationCodeFailures
                | Limit::Recovery
                | Limit::UserLookup
                | Limit::FedUsers
        )
    }

    /// Whether one account may get its own value (docs/plans/admin-rate-limits.md
    /// §4): the limits counted per signed-in account. The sign-in ceilings
    /// count guesses at an account, not its own use, so they take none.
    pub fn overridable(&self) -> bool {
        // A forwarding's limits are its account's to override too.
        matches!(self.per, Per::Account | Per::Forwarding)
            && !matches!(
                self.limit,
                Limit::LoginAccountCeiling | Limit::LoginAccountDailyCeiling
            )
    }

    /// The highest value it takes: 100 times its default, so a typo
    /// cannot turn it off. On a test stack (`RATE_LIMITS_RELAXED`, test
    /// only) the `RATE_LIMIT_*` ones may go up to the relaxed value, except
    /// those that guard against guessing. The lowest is 1.
    pub fn ceiling(&self, test_stack: bool) -> u64 {
        let ceiling = self.default.saturating_mul(100);
        if test_stack && self.relaxed() && !self.guards_guessing() {
            ceiling.max(RELAXED)
        } else {
            ceiling
        }
    }
}

/// Every limit, in [`SPECS`]'s order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Limit {
    // Accounts and sign-in.
    Login,
    LoginLockoutThreshold,
    LoginLockoutMinutes,
    LoginAccountCeiling,
    LoginAccountDailyCeiling,
    LoginSourceDailyCeiling,
    TotpAttempts,
    TotpBlockMinutes,
    Fork,
    Register,
    RegistrationCodeChecks,
    RegistrationCodeFailures,
    Recovery,
    UserLookup,
    DeviceChallenges,
    AccountHeadReads,
    RenameChecks,
    RenameLookups,
    Feedback,
    // Drive.
    AvailableHashes,
    CollabFramePosts,
    CollabFramesPerSecond,
    CollabFrameBurst,
    CollabBytesPerSecond,
    CollabByteBurst,
    Reports,
    // Chat.
    ChatKeysAccount,
    ChatKeysAddress,
    ChatAnonymousAddress,
    SealedCapabilityBundles,
    SealedCapabilityMinute,
    SealedCapabilityDay,
    SealedRecipient,
    SealedOrigin,
    MediaCapabilityMinute,
    MediaCapabilityDay,
    MediaRecipient,
    MediaOrigin,
    LinkPreviews,
    LiveLocationStreams,
    LiveLocationReads,
    // Groups.
    GroupRelay,
    GroupGatewayRelay,
    GroupPseudonym,
    GroupChangesPseudonym,
    GroupChangesGroup,
    GroupLink,
    GroupFailuresRelay,
    GroupCreatesRelay,
    InviteLinkAccountCalls,
    InviteLinkAccountRequests,
    InviteLinkOriginCalls,
    GroupCallAccountTokens,
    GroupCallOriginTokens,
    // Mail.
    MailDomainChecks,
    MailImages,
    MailImageBytes,
    MailImagesAtOnce,
    MailImagesServerAtOnce,
    ForwardingConfirmations,
    ForwardingsCreated,
    ForwardingConfirmationsSent,
    ForwardingInvites,
    ForwardingCodeMinutes,
    ForwardingCodeAttempts,
    ForwardingCodeResends,
    ForwardingCodesPerDestination,
    ForwardingUnverifiedPending,
    ForwardingUnverifiedMinutes,
    ForwardingBounces,
    ForwardingOutside,
    ForwardingOutsideAccount,
    // Calendar.
    CalendarWrites,
    // Calls and maps.
    CallLinks,
    CallLinkPolls,
    TurnCredentials,
    MapTiles,
    // Pass.
    PassIcons,
    PassIconFetches,
    PassPinAttempts,
    // Federation.
    FedUsers,
    FedMultiFailures,
    RenamePeerFetches,
    AccountPeerFetches,
    RenameAnnounces,
    CollabDeviceAnnounces,
    // Administration.
    Admin,
}

const SECOND: Duration = Duration::from_secs(1);
const MINUTE: Duration = Duration::from_secs(60);
const QUARTER_HOUR: Duration = Duration::from_secs(15 * 60);
const HOUR: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_secs(24 * 3600);

macro_rules! spec {
    ($limit:ident, $key:literal, $env:expr, $default:expr, $unit:expr, $per:ident, $section:ident, $about:literal) => {
        Spec {
            limit: Limit::$limit,
            key: $key,
            env: $env,
            default: $default,
            unit: $unit,
            per: Per::$per,
            section: Section::$section,
            about: $about,
        }
    };
}

use Unit::{AtOnce, Attempts, Bytes, BytesAtOnce, Events, EventsPerLockout, Minutes};

const MIB: u64 = 1024 * 1024;

pub static SPECS: &[Spec] = &[
    spec!(
        Login,
        "login",
        Some("RATE_LIMIT_LOGIN_PER_MIN"),
        10,
        Events(MINUTE),
        Address,
        Accounts,
        "Sign-in attempts (and their second factor)."
    ),
    spec!(
        LoginLockoutThreshold,
        "login_lockout_threshold",
        Some("LOGIN_LOCKOUT_THRESHOLD"),
        5,
        Attempts,
        AccountAndClient,
        Accounts,
        "Wrong secrets for one account from one client before that pair is locked out."
    ),
    spec!(
        LoginLockoutMinutes,
        "login_lockout_minutes",
        Some("LOGIN_LOCKOUT_MINUTES"),
        15,
        Minutes,
        AccountAndClient,
        Accounts,
        "How long a lockout lasts, and the window of the account ceiling."
    ),
    spec!(
        LoginAccountCeiling,
        "login_account_ceiling",
        Some("LOGIN_ACCOUNT_CEILING"),
        20,
        EventsPerLockout,
        Account,
        Accounts,
        "Sign-in attempts on one account from clients it does not know, all together."
    ),
    spec!(
        LoginAccountDailyCeiling,
        "login_account_daily_ceiling",
        Some("LOGIN_ACCOUNT_DAILY_CEILING"),
        200,
        Events(DAY),
        Account,
        Accounts,
        "The same, per day: the cap on guessing spread over many addresses."
    ),
    spec!(
        LoginSourceDailyCeiling,
        "login_source_daily_ceiling",
        Some("LOGIN_SOURCE_DAILY_CEILING"),
        20,
        Events(DAY),
        AccountAndClient,
        Accounts,
        "One client's share of an account's daily ceiling."
    ),
    spec!(
        TotpAttempts,
        "totp_attempts",
        None,
        5,
        Attempts,
        SignIn,
        Accounts,
        "Wrong second-factor codes before a sign-in is blocked."
    ),
    spec!(
        TotpBlockMinutes,
        "totp_block_minutes",
        None,
        15,
        Minutes,
        SignIn,
        Accounts,
        "How long a blocked sign-in stays blocked."
    ),
    spec!(
        Fork,
        "fork",
        Some("RATE_LIMIT_FORK_PER_MIN"),
        120,
        Events(MINUTE),
        Address,
        Accounts,
        "Sessions handed to an app (every app opened redeems one)."
    ),
    spec!(
        Register,
        "register",
        Some("RATE_LIMIT_REGISTER_PER_HOUR"),
        10,
        Events(HOUR),
        Address,
        Accounts,
        "Sign-ups: scripted account spam on open registration."
    ),
    spec!(
        RegistrationCodeChecks,
        "registration_code_checks",
        Some("RATE_LIMIT_REGISTRATION_CODE_CHECK_PER_HOUR"),
        30,
        Events(HOUR),
        Address,
        Accounts,
        "Referral codes checked before signing up, valid or not."
    ),
    spec!(
        RegistrationCodeFailures,
        "registration_code_failures",
        Some("RATE_LIMIT_REGISTRATION_CODE_FAILURES_PER_HOUR"),
        20,
        Events(HOUR),
        Address,
        Accounts,
        "Referral codes that admitted no one: guessing codes."
    ),
    spec!(
        Recovery,
        "recovery",
        Some("RATE_LIMIT_RECOVERY_PER_HOUR"),
        5,
        Events(HOUR),
        Address,
        Accounts,
        "Account recovery attempts."
    ),
    spec!(
        UserLookup,
        "user_lookup",
        Some("RATE_LIMIT_USER_LOOKUP_PER_MIN"),
        30,
        Events(MINUTE),
        Address,
        Accounts,
        "Looking users up to share with: enumerating accounts."
    ),
    spec!(
        DeviceChallenges,
        "device_challenges",
        Some("RATE_LIMIT_DEVICE_CHALLENGES_PER_MIN"),
        20,
        Events(MINUTE),
        Account,
        Accounts,
        "Device registration challenges."
    ),
    spec!(
        AccountHeadReads,
        "account_head_reads",
        Some("RATE_LIMIT_ACCOUNT_HEAD_READS_PER_MIN"),
        300,
        Events(MINUTE),
        Account,
        Accounts,
        "Reads of the account head, its chain and a scope's index."
    ),
    spec!(
        RenameChecks,
        "rename_checks",
        Some("RATE_LIMIT_RENAME_CHECKS_PER_15_MIN"),
        30,
        Events(QUARTER_HOUR),
        Account,
        Accounts,
        "Name checks before a rename."
    ),
    spec!(
        RenameLookups,
        "rename_lookups",
        Some("RATE_LIMIT_RENAME_LOOKUPS_PER_15_MIN"),
        60,
        Events(QUARTER_HOUR),
        Account,
        Accounts,
        "Another server's renames asked of it (lookups that found nothing kept)."
    ),
    spec!(
        Feedback,
        "feedback",
        Some("RATE_LIMIT_FEEDBACK_PER_HOUR"),
        10,
        Events(HOUR),
        Account,
        Accounts,
        "Feedback sent: filling the administrators' inbox."
    ),
    spec!(
        AvailableHashes,
        "available_hashes",
        Some("RATE_LIMIT_AVAILABLE_HASHES_PER_MIN"),
        120,
        Events(MINUTE),
        Account,
        Drive,
        "Name checks (\"Keep both\"): guessing names fast."
    ),
    spec!(
        CollabFramePosts,
        "collab_frame_posts",
        Some("RATE_LIMIT_COLLAB_FRAME_POSTS_PER_MIN"),
        600,
        Events(MINUTE),
        Device,
        Drive,
        "Collaboration frames sent over HTTP (the CLI)."
    ),
    spec!(
        CollabFramesPerSecond,
        "collab_frames_per_second",
        None,
        50,
        Events(SECOND),
        Connection,
        Drive,
        "Collaboration frames one socket sends a second, on average."
    ),
    spec!(
        CollabFrameBurst,
        "collab_frame_burst",
        None,
        500,
        AtOnce,
        Connection,
        Drive,
        "Collaboration frames one socket may send in a burst."
    ),
    spec!(
        CollabBytesPerSecond,
        "collab_bytes_per_second",
        None,
        MIB,
        Bytes(SECOND),
        Connection,
        Drive,
        "Collaboration bytes one socket sends a second, on average."
    ),
    spec!(
        CollabByteBurst,
        "collab_byte_burst",
        None,
        16 * MIB,
        BytesAtOnce,
        Connection,
        Drive,
        "Collaboration bytes one socket may send in a burst."
    ),
    spec!(
        Reports,
        "reports",
        Some("RATE_LIMIT_REPORT_PER_HOUR"),
        20,
        Events(HOUR),
        Address,
        Drive,
        "Reports on public links, which need no account."
    ),
    spec!(
        ChatKeysAccount,
        "chat_keys_account",
        Some("RATE_LIMIT_CHAT_KEYS_PER_MIN"),
        30,
        Events(MINUTE),
        Account,
        Chat,
        "Key bundles fetched: draining one-time prekeys."
    ),
    spec!(
        ChatKeysAddress,
        "chat_keys_address",
        Some("RATE_LIMIT_CHAT_KEYS_IP_PER_MIN"),
        120,
        Events(MINUTE),
        Address,
        Chat,
        "The outer wall on key bundles fetched."
    ),
    spec!(
        ChatAnonymousAddress,
        "chat_anonymous_address",
        Some("RATE_LIMIT_CHAT_ANONYMOUS_IP_PER_MIN"),
        60,
        Events(MINUTE),
        Address,
        Chat,
        "The outer wall on sealed-sender deliveries."
    ),
    spec!(
        SealedCapabilityBundles,
        "sealed_capability_bundles",
        None,
        30,
        Events(MINUTE),
        Capability,
        Chat,
        "Key bundles fetched with one sealed-sender capability."
    ),
    spec!(
        SealedCapabilityMinute,
        "sealed_capability_minute",
        None,
        120,
        Events(MINUTE),
        Capability,
        Chat,
        "Sealed messages sent with one capability."
    ),
    spec!(
        SealedCapabilityDay,
        "sealed_capability_day",
        None,
        10_000,
        Events(DAY),
        Capability,
        Chat,
        "The same, per day."
    ),
    spec!(
        SealedRecipient,
        "sealed_recipient",
        None,
        120,
        Events(MINUTE),
        Recipient,
        Chat,
        "Sealed messages one person receives."
    ),
    spec!(
        SealedOrigin,
        "sealed_origin",
        None,
        600,
        Events(MINUTE),
        Peer,
        Chat,
        "Sealed messages one peer server delivers, answered or not."
    ),
    spec!(
        MediaCapabilityMinute,
        "media_capability_minute",
        None,
        120,
        Events(MINUTE),
        Capability,
        Chat,
        "Sealed attachments sent with one capability."
    ),
    spec!(
        MediaCapabilityDay,
        "media_capability_day",
        None,
        10_000,
        Events(DAY),
        Capability,
        Chat,
        "The same, per day."
    ),
    spec!(
        MediaRecipient,
        "media_recipient",
        None,
        120,
        Events(MINUTE),
        Recipient,
        Chat,
        "Sealed attachments one person receives."
    ),
    spec!(
        MediaOrigin,
        "media_origin",
        None,
        600,
        Events(MINUTE),
        Peer,
        Chat,
        "Sealed attachments one peer server delivers."
    ),
    spec!(
        LinkPreviews,
        "link_previews",
        None,
        30,
        Events(MINUTE),
        Account,
        Chat,
        "Link previews fetched (a page and an image each)."
    ),
    spec!(
        LiveLocationStreams,
        "live_location_streams",
        None,
        60,
        Events(HOUR),
        Account,
        Chat,
        "Live-location streams started."
    ),
    spec!(
        LiveLocationReads,
        "live_location_reads",
        None,
        600,
        Events(MINUTE),
        Account,
        Chat,
        "Live-location reads across streams."
    ),
    spec!(
        GroupRelay,
        "group_relay",
        Some("RATE_LIMIT_CHAT_GROUP_RELAY_PER_MIN"),
        240,
        Events(MINUTE),
        Account,
        Groups,
        "Requests through the groups relay."
    ),
    spec!(
        GroupGatewayRelay,
        "group_gateway_relay",
        Some("RATE_LIMIT_CHAT_GROUP_GATEWAY_RELAY_PER_MIN"),
        6000,
        Events(MINUTE),
        Peer,
        Groups,
        "Requests from one relay server's users together."
    ),
    spec!(
        GroupPseudonym,
        "group_pseudonym",
        Some("RATE_LIMIT_CHAT_GROUP_PSEUDONYM_PER_MIN"),
        240,
        Events(MINUTE),
        Pseudonym,
        Groups,
        "Requests from one member."
    ),
    spec!(
        GroupChangesPseudonym,
        "group_changes_pseudonym",
        Some("RATE_LIMIT_CHAT_GROUP_CHANGES_PSEUDONYM_PER_MIN"),
        30,
        Events(MINUTE),
        Pseudonym,
        Groups,
        "Group changes by one member."
    ),
    spec!(
        GroupChangesGroup,
        "group_changes_group",
        Some("RATE_LIMIT_CHAT_GROUP_CHANGES_GROUP_PER_MIN"),
        60,
        Events(MINUTE),
        Group,
        Groups,
        "Group changes to one group: many members flooding one log."
    ),
    spec!(
        GroupLink,
        "group_link",
        Some("RATE_LIMIT_CHAT_GROUP_LINK_PER_MIN"),
        30,
        Events(MINUTE),
        Group,
        Groups,
        "Join information asked through a group's link."
    ),
    spec!(
        GroupFailuresRelay,
        "group_failures_relay",
        Some("RATE_LIMIT_CHAT_GROUP_FAILURES_RELAY_PER_MIN"),
        600,
        Events(MINUTE),
        Peer,
        Groups,
        "Failed group requests from one relay server."
    ),
    spec!(
        GroupCreatesRelay,
        "group_creates_relay",
        Some("RATE_LIMIT_CHAT_GROUP_CREATES_RELAY_PER_HOUR"),
        600,
        Events(HOUR),
        Peer,
        Groups,
        "New groups from one relay server."
    ),
    spec!(
        InviteLinkAccountCalls,
        "invite_link_account_calls",
        None,
        120,
        Events(MINUTE),
        Account,
        Groups,
        "Invite-link requests by one account."
    ),
    spec!(
        InviteLinkAccountRequests,
        "invite_link_account_requests",
        None,
        10,
        Events(HOUR),
        Account,
        Groups,
        "Requests to join through invite links by one account."
    ),
    spec!(
        InviteLinkOriginCalls,
        "invite_link_origin_calls",
        None,
        600,
        Events(MINUTE),
        Peer,
        Groups,
        "Invite-link requests from one peer server."
    ),
    spec!(
        GroupCallAccountTokens,
        "group_call_account_tokens",
        None,
        30,
        Events(MINUTE),
        Account,
        Groups,
        "Group-call tokens asked by one account."
    ),
    spec!(
        GroupCallOriginTokens,
        "group_call_origin_tokens",
        None,
        300,
        Events(MINUTE),
        Peer,
        Groups,
        "Group-call tokens asked by one peer server."
    ),
    spec!(
        MailDomainChecks,
        "mail_domain_checks",
        Some("RATE_LIMIT_MAIL_DOMAIN_CHECKS_PER_HOUR"),
        30,
        Events(HOUR),
        Account,
        Mail,
        "A custom domain's \"Refresh status\" (uncached lookups)."
    ),
    spec!(
        MailImages,
        "mail_images",
        None,
        120,
        Events(MINUTE),
        Account,
        Mail,
        "Remote images fetched through the image proxy."
    ),
    spec!(
        MailImageBytes,
        "mail_image_bytes",
        None,
        64 * MIB,
        Bytes(MINUTE),
        Account,
        Mail,
        "Remote image bytes fetched through the proxy."
    ),
    spec!(
        MailImagesAtOnce,
        "mail_images_at_once",
        None,
        6,
        AtOnce,
        Account,
        Mail,
        "Remote images one account fetches at once."
    ),
    spec!(
        MailImagesServerAtOnce,
        "mail_images_server_at_once",
        None,
        32,
        AtOnce,
        Server,
        Mail,
        "Remote images the server fetches at once, for everyone."
    ),
    spec!(
        ForwardingConfirmations,
        "forwarding_confirmations",
        None,
        30,
        Events(MINUTE),
        Address,
        Mail,
        "Requests to the public forwarding confirmation page."
    ),
    spec!(
        ForwardingsCreated,
        "forwardings_created",
        None,
        10,
        Events(HOUR),
        Account,
        Mail,
        "Forwardings one account makes."
    ),
    spec!(
        ForwardingConfirmationsSent,
        "forwarding_confirmations_sent",
        None,
        10,
        Events(DAY),
        Account,
        Mail,
        "Verification code emails one account causes, across its forwardings."
    ),
    spec!(
        ForwardingInvites,
        "forwarding_invites",
        None,
        10,
        Events(DAY),
        Forwarding,
        Mail,
        "Verification codes one forwarding sends."
    ),
    spec!(
        ForwardingCodeMinutes,
        "forwarding_code_minutes",
        None,
        15,
        Minutes,
        Forwarding,
        Mail,
        "How long a forwarding's verification code lasts."
    ),
    spec!(
        ForwardingCodeAttempts,
        "forwarding_code_attempts",
        None,
        5,
        Attempts,
        Forwarding,
        Mail,
        "Wrong verification codes before the code is void and a new one is needed."
    ),
    spec!(
        ForwardingCodeResends,
        "forwarding_code_resends",
        None,
        1,
        Events(MINUTE),
        Forwarding,
        Mail,
        "Verification codes one forwarding may send in a minute."
    ),
    spec!(
        ForwardingCodesPerDestination,
        "forwarding_codes_per_destination",
        None,
        10,
        Events(DAY),
        Recipient,
        Mail,
        "Verification codes one destination address receives in a day, from every account."
    ),
    spec!(
        ForwardingUnverifiedPending,
        "forwarding_unverified_pending",
        None,
        5,
        AtOnce,
        Account,
        Mail,
        "Forwardings one account may have waiting for their code at once."
    ),
    spec!(
        ForwardingUnverifiedMinutes,
        "forwarding_unverified_minutes",
        None,
        1440,
        Minutes,
        Forwarding,
        Mail,
        "How long after its last code an unverified forwarding lapses."
    ),
    spec!(
        ForwardingBounces,
        "forwarding_bounces",
        None,
        5,
        Events(DAY),
        Forwarding,
        Mail,
        "Bounces that pause an outside forwarding."
    ),
    spec!(
        ForwardingOutside,
        "forwarding_outside",
        None,
        200,
        Events(DAY),
        Forwarding,
        Mail,
        "Messages one forwarding re-sends outside."
    ),
    spec!(
        ForwardingOutsideAccount,
        "forwarding_outside_account",
        None,
        500,
        Events(DAY),
        Account,
        Mail,
        "Messages one account's forwardings re-send outside."
    ),
    spec!(
        CalendarWrites,
        "calendar_writes",
        None,
        600,
        Events(MINUTE),
        Account,
        Calendar,
        "Calendar changes: calendars made or changed and event syncs."
    ),
    spec!(
        CallLinks,
        "call_links",
        Some("RATE_LIMIT_CALL_LINK_PER_MIN"),
        60,
        Events(MINUTE),
        Address,
        CallsAndMaps,
        "Calls opened and joined through a link, which need no account."
    ),
    spec!(
        CallLinkPolls,
        "call_link_polls",
        Some("RATE_LIMIT_CALL_LINK_POLL_PER_MIN"),
        600,
        Events(MINUTE),
        Address,
        CallsAndMaps,
        "Waiting to be let into a meeting, and watching who waits."
    ),
    spec!(
        TurnCredentials,
        "turn_credentials",
        None,
        60,
        Events(MINUTE),
        Account,
        CallsAndMaps,
        "Call relay (TURN) credentials asked."
    ),
    spec!(
        MapTiles,
        "map_tiles",
        None,
        1200,
        Events(MINUTE),
        Account,
        CallsAndMaps,
        "Map tiles through the map proxy: a runaway client."
    ),
    spec!(
        PassIcons,
        "pass_icons",
        None,
        600,
        Events(MINUTE),
        Account,
        Pass,
        "Site icons answered (a large vault asks for many)."
    ),
    spec!(
        PassIconFetches,
        "pass_icon_fetches",
        None,
        120,
        Events(MINUTE),
        Account,
        Pass,
        "Sites fetched for icons (what the cache answers does not count)."
    ),
    spec!(
        PassPinAttempts,
        "pass_pin_attempts",
        None,
        3,
        Attempts,
        SignIn,
        Pass,
        "Wrong PINs in a row before the sign-in ends."
    ),
    spec!(
        FedUsers,
        "fed_users",
        Some("RATE_LIMIT_FED_USERS_PER_MIN"),
        60,
        Events(MINUTE),
        Address,
        Federation,
        "Username lookups from other servers."
    ),
    spec!(
        FedMultiFailures,
        "fed_multi_failures",
        Some("RATE_LIMIT_FED_MULTI_FAILURES_PER_MIN"),
        60,
        Events(MINUTE),
        Address,
        Federation,
        "Forwarded group sends that do not authenticate."
    ),
    spec!(
        RenamePeerFetches,
        "rename_peer_fetches",
        Some("RATE_LIMIT_RENAME_PEER_FETCHES_PER_MIN"),
        120,
        Events(MINUTE),
        Peer,
        Federation,
        "Renames fetched from one peer, whoever asks."
    ),
    spec!(
        AccountPeerFetches,
        "account_peer_fetches",
        Some("RATE_LIMIT_ACCOUNT_PEER_FETCHES_PER_MIN"),
        120,
        Events(MINUTE),
        AccountAndPeer,
        Federation,
        "Accounts one account asks of one peer by id."
    ),
    spec!(
        RenameAnnounces,
        "rename_announces",
        Some("RATE_LIMIT_RENAME_ANNOUNCES_PER_MIN"),
        600,
        Events(MINUTE),
        Peer,
        Federation,
        "Rename announces taken from one peer."
    ),
    spec!(
        CollabDeviceAnnounces,
        "collab_device_announces",
        Some("RATE_LIMIT_COLLAB_DEVICE_ANNOUNCES_PER_MIN"),
        60,
        Events(MINUTE),
        PeerAndShare,
        Federation,
        "Device announces from another server for one share."
    ),
    spec!(
        Admin,
        "admin",
        Some("RATE_LIMIT_ADMIN_PER_MIN"),
        120,
        Events(MINUTE),
        Address,
        Administration,
        "Admin API requests: a wall for a script."
    ),
];

/// Variables accepted for what is not a limit here: the first values of two
/// administrators' settings (`site_settings::chat_group_link_joins`), and a
/// retired limit (the login preflight; OPAQUE has none) still accepted so a
/// server whose environment sets it starts.
pub const ENV_SEEDS: &[(&str, u64)] = &[
    ("RATE_LIMIT_CHAT_GROUP_LINK_JOINS_RELAY_GROUP_PER_MIN", 120),
    ("RATE_LIMIT_CHAT_GROUP_LINK_JOINS_RELAY_PER_MIN", 1200),
    ("RATE_LIMIT_PREFLIGHT_PER_MIN", 20),
];

impl Limit {
    pub fn spec(self) -> &'static Spec {
        &SPECS[self as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn specs_follow_the_enum_and_names_are_unique() {
        let mut keys = HashSet::new();
        let mut envs = HashSet::new();
        for (index, spec) in SPECS.iter().enumerate() {
            assert_eq!(spec.limit as usize, index, "{} is out of order", spec.key);
            assert!(keys.insert(spec.key), "{} twice", spec.key);
            if let Some(env) = spec.env {
                assert!(envs.insert(env), "{env} twice");
                assert!(!ENV_SEEDS.iter().any(|(seed, _)| *seed == env));
            }
            assert!(spec.default >= 1 && spec.ceiling(false) >= spec.default);
            assert!(spec.ceiling(true) >= spec.ceiling(false));
            if spec.guards_guessing() {
                assert_eq!(spec.ceiling(true), spec.default * 100, "{}", spec.key);
            }
            assert!(spec
                .key
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'_'));
        }
        assert_eq!(Limit::Admin as usize + 1, SPECS.len());
    }

    /// Administration → Rate limits names every limit and says what it
    /// stops, in each language.
    #[test]
    fn the_admin_page_names_every_limit() {
        for language in ["en", "tr"] {
            let path = format!(
                "{}/../../frontend/apps/account/src/locales/{language}.json",
                env!("CARGO_MANIFEST_DIR")
            );
            let text = std::fs::read_to_string(&path).expect("the account app's strings");
            let strings: serde_json::Value = serde_json::from_str(&text).expect("JSON");
            for part in ["limit", "about"] {
                let texts = &strings["admin"]["rateLimits"][part];
                for spec in SPECS {
                    assert!(
                        texts[spec.key].is_string(),
                        "{language} {part}: {}",
                        spec.key
                    );
                }
                assert_eq!(
                    texts.as_object().map(|texts| texts.len()),
                    Some(SPECS.len())
                );
            }
        }
    }
}
