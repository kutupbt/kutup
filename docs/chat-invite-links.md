# Kutup group invite links

A group link lets someone join a private MLS group without an administrator
typing their address, as Signal's group links do. Anyone holding the link
sees the group's name, picture, description and size, and asks to join;
depending on the group's setting an administrator approves each request, or
an administrator's client adds whoever asks.

## The link

`https://<chat app>/join#<fragment>`, where the fragment is base64url (no
padding) of `0x01 || secret (32 bytes) || host (UTF-8)`:

- `secret`: random, made by the administrator's client;
- `host`: the domain of the server that keeps the link's mailbox, the
  server of the administrator who turned the link on or last reset it.

Browsers never send the fragment to a server. The chat app opens any
server's `/join#…` link in place, whether it is opened directly, clicked in a
message, or pasted into "Join with a link" (or the new-chat address field).

The link itself (`secret`, `host`, `approvalRequired`) is the optional
`inviteLink` of the group information (`MlsGroupInfoV1`, see
[`chat-mls.md`](chat-mls.md) "Group information"), so every member has it and
can share it while it is on. Only administrators change it, whatever the
group's editing policy: turning it on or off, resetting it, and switching
approval are `GroupInfoChange` Commits that every member's engine refuses
from a non-administrator (the sender leaf is authenticated first). Each
change leaves a timeline notice ("Alice turned on the group link with admin
approval."). Recovery carries the link into the new incarnation.

## Keys

From the secret, HKDF-SHA256 (salt `kutup/chat/invite-link/v1`) derives three
32-byte values with the labels `link id`, `manage token` and `seal key`:

| Value | Used for |
| --- | --- |
| `linkId` | the mailbox's name on the host (standard base64) |
| `manageToken` | members' authority over the mailbox; the host stores only its SHA-256 |
| seal key | XChaCha20-Poly1305 over the preview and the requests |

A sealed value is `nonce (24) || ciphertext`, with the associated data
`kutup/chat/invite-link/v1/<preview|request> 0x00 linkId`, over a plaintext
of `length (u32 BE) || JSON || zeros`, padded to a multiple of 4096 bytes
(preview, at most 80 KiB sealed) or 256 bytes (request, at most 1 KiB). The
Rust engine (`kutup-chat-core` `invite_link.rs`) owns this format; the
browser reaches it through WASM.

## The mailbox

The host keeps, per `linkId`:

- the sealed **preview** (`InviteLinkPreviewV1`: conversation id, name,
  description, picture, member count, whether approval is needed), written
  by administrators' clients whenever it differs from the group;
- the sealed **requests** (`InviteJoinRequestV1`: the requester's canonical
  address and time), each with the server it came through, a status
  (pending, approved, denied) and the SHA-256 of a token the requester chose.

Every operation is one `InviteLinkOperationV1` (`put`, `delete`, `preview`,
`request`, `requests`, `decide`, `status`, `cancel`). An account sends it to
its own server (`POST /api/chat/invite-links` with the host); a remote host is
reached over signed federation (`POST /api/fed/chat/invite-links`), and the
host records the authenticated origin domain as the request's server.
Holders of the link read the preview and ask; holders of the manage token
(members) read the requests, decide them, replace the preview or delete the
mailbox; a requester reads or cancels only its own request.

Limits: 256 pending requests per link and 32 per requesting server, 10 new
requests per account per hour and 120 operations per account per minute, 600
federated operations per origin per minute, 10,000 mailboxes per origin
server. The host forgets a mailbox nobody has read for 90 days, decided
requests after a week and undecided ones after 90 days; members' clients
recreate a live link's mailbox when it is missing.

## Joining

1. The requester's client opens the preview and shows it. Already a member:
   it offers to open the group.
2. "Join" or "Request to join" seals the request and stores, in this
   browser, the link, request id and status token.
3. Administrators' clients read the mailbox (every 15 s for a link anyone
   may use, every 60 s when approval is needed, and when the group's details
   open). They turn away a request that does not open or whose requester's
   server differs from the server it came through, approve one from a
   current member, and otherwise:
   - without approval, the first administrator by canonical address adds
     the requester with an ordinary MLS addition (any administrator does
     after five minutes, so an absent one does not block joining);
   - with approval, the request shows in the group ("1 person wants to
     join") until an administrator approves (the addition) or denies it.
4. The addition sends the usual invitation. The requester's client accepts
   it by itself because it matches a stored request; it learns of a denial
   (or a link that stopped working) by asking the host for its request's
   status.

Joining without approval therefore needs one of the group's administrators
to be online, unlike Signal, whose server adds the member: an MLS addition
must be committed by a member.

## What servers learn

The host learns that a mailbox exists, its size and activity, and which
servers requests came from and when; never the group, its members, or who
asked. The requester's server learns that its account used a link hosted
elsewhere. Neither can read a preview or a request, forge a preview, or add
anyone: additions stay MLS Commits by administrators.

A malicious server could seal a request naming another of its own accounts.
The effect is an invitation that account can decline, the same as an
administrator inviting it; a server cannot name accounts of other servers.
Link holders can also delete the mailbox or deny requests; administrators
recover by resetting the link.
