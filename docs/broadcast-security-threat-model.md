# Confidential broadcast V1 threat model

**Status:** normative V1 completion gate

Broadcast channels are one-way encrypted feeds for up to 1,000,000 subscribed
accounts and ten devices per account. Subscribers are not members of the MLS
administrator group.

## Roles and trust

- Owners and administrators form a small OpenMLS control group. Existing
  replaceable ordering authorities certify its ordered control log.
- Administrators may publish and see the canonical subscriber roster.
- Owners additionally hold subscriber-tree state and commit membership
  rekeys. Removing an owner therefore requires a complete tree rebuild.
- Every subscriber occupies one Logical Key Hierarchy account leaf. The
  account's channel access secret is wrapped independently to its active
  manifest-bound devices.
- Subscriber homeservers pull and cache one opaque signed post. Posts are not
  encrypted once per account or device.

## Threats and required results

| Threat | Required control and result |
|---|---|
| Removed subscriber reads a later post | Removal remains pending and publishing is blocked until the account path and content epoch rotate. |
| Removed device continues through a sibling device grant | Rotate the account's channel access secret and wrap it only to remaining manifest devices before publishing resumes. |
| New subscriber reads more history than policy allows | A channel policy fixes `history_window_days` in `0..=365`; bounded daily history grants contain no earlier content keys. |
| Subscriber forges a post | Posts require an active publisher signature and exact ordered channel-control epoch. Symmetric subscriber keys never authorize publishing. |
| Removed administrator publishes | MLS control-group removal advances its secret and publisher authorization before the next post. Administrators do not hold subscriber-tree state. |
| Removed owner retains tree secrets | Publishing stops while a resumable full account-tree rebuild distributes fresh state to current accounts. Old tree material never encrypts a later post. |
| Authority or storage server rewrites the feed | Hash-linked ordered control/post records, publisher signatures and durable client cursors reject rollback, gaps, conflicts and replay. |
| One server outage takes down history | Authority replicas and subscriber homeserver caches retain opaque posts. Loss of ordering quorum stops new posts/control writes but cached reads continue. |
| Roster enumeration | Subscribers do not receive the complete roster. Administrators and involved homeservers are explicitly allowed to learn subscription relationships; V1 does not hide them. |
| Scale causes unbounded work | Fixed tree depth gives logarithmic ordinary rekeys; device grants and owner rebuilds are streamed and restartable with bounded memory. |

## Capacity definitions

- `maximum_channel_accounts = 1_000_000`.
- `maximum_active_chat_devices_per_account <= 10`.
- The implementation therefore supports up to 10,000,000 independently
  usable encrypted device grants.
- A channel post has one ciphertext plus bounded authority replication. The
  million-account tree is touched only for membership/key-management events.

Scale tests use the exact logical account and device-grant counts. Browser E2E
uses a smaller real deployment while the identical verifier, storage and
streaming code is exercised by the full logical benchmark.
