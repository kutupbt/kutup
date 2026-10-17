# Hidden group membership across federated servers

Date: 2026-10-17. Research for [`plans/pairwise-groups.md`](../plans/pairwise-groups.md).
**Outcome:** the user chose design (e), per-group pseudonymous member keys, on
2026-10-17. The group's home is fixed (the server where the group was created),
and the roles are Signal's administrator and member.

**The user's requirement (2026-10-17).** "The server must not be able to see
members." Neither the group's home server nor the members' own servers may
learn who is in a group. Signal's groups server achieves this with zkgroup,
and the requirement applies to version 1 of groups.

**The question.** Can Signal's Private Group System work when members are on
many servers? If it can't, what design meets the requirement?

**The answer in one paragraph.**
- Signal's zero-knowledge credentials don't federate. They are
  keyed-verification credentials: only a holder of the issuer's secret key can
  verify them, and Signal relies on one operator that both knows who an account
  is and checks it.
- No publicly verifiable replacement is mature enough to build on.
- The requirement can still be met, without zero knowledge: **per-group
  pseudonymous member keys**.
  - The home server keeps and checks a membership of keys it can't link to
    accounts.
  - The key→account binding is encrypted for members.
  - Requests reach the home through the member's own server as Oblivious-HTTP
    style opaque blobs.
- The home then sees what Signal's groups server sees: the number of members,
  an opaque id per member per group, roles and change timing. The members'
  servers see less than in today's direct chats.
- What leaks regardless is network metadata, listed honestly below.

Sources:
- libsignal v0.97.2, the tag chat-core pins: `rust/zkgroup`, `rust/zkcredential`
  in the Cargo checkout;
- `Signal-Desktop` and `Signal-Server` in `kutup-references/`;
- Chase, Perrin and Zaverucha, "The Signal Private Group System and Anonymous
  Credentials Supporting Efficient Verifiable Encryption" (CCS 2020,
  [ePrint 2019/1416](https://eprint.iacr.org/2019/1416)).

Two research agents for the literature survey stopped at a usage limit. The
code facts below were read directly. The literature section is shorter than
planned and says where it is unverified.

## 1. How Signal's Private Group System works

**The credentials are MACs, not signatures.**
- `zkcredential` describes a credential as "essentially a MAC over several
  attributes" (`zkcredential/src/lib.rs:20-23`). It is the keyed-verification
  anonymous credential (KVAC) of the CPZ paper, on ristretto255, with Schnorr
  proofs (`poksho`).
- Verifying a presentation takes the issuer's key pair, secret part included:
  `verify(&self, ..., key_pair: &CredentialKeyPair, ...)`
  (`zkcredential/src/presentation.rs:640-642`).
- The crate states the trust model itself: "the issuing and verifying servers
  share their private keys, but may otherwise be independent; for Signal, the
  issuing server is usually the main chat server (which knows who the client
  is), and the verifying server is the 'storage service' where groups are
  managed (which must not)" (`lib.rs:25-29`).

**Groups v2 with them.**
- **Group parameters.** A group's master key gives `GroupSecretParams`. With it
  a client encrypts each member's account id deterministically:
  `encrypt_service_id` → `UuidCiphertext` (`zkgroup/src/api/groups/group_params.rs:105`).
- **What the server stores.** It keeps only those ciphertexts, with roles.
- **Each request.** The client presents its `AuthCredentialWithPni`, issued by
  the chat server on its ACI, as a zero-knowledge proof that "the ciphertext in
  this group encrypts the id in my credential"
  (`server_params.rs:173`, `verify_auth_credential_presentation`).
- **What the server learns.** It learns which stored ciphertext is acting, never
  the account.
- **Adding a member.** This uses a profile-key credential presentation, which
  proves that the added ciphertexts are of a real account and its profile key.

**Group send endorsements.**
- Since 2024, the groups server issues *endorsements* that the chat server
  checks before accepting a sealed multi-recipient send.
- They prove that the sender is in a group with exactly these recipients.
- They are also MACs (3HashSDHI, `zkcredential/src/endorsements.rs:1-25`).
  Verifying a token needs the derived private key
  (`ServerDerivedKeyPair::verify`, `endorsements.rs:622-627`), which comes from
  a root key both servers hold (`group_send_endorsement.rs:54-60`).

**The only publicly verifiable piece** is the server's notary signature on
group changes (`ServerPublicParams::verify_signature`, `server_params.rs:359-365`),
an ordinary signature.

**What Signal's groups server still sees** (`Groups.proto`; the earlier
research in [`pairwise-groups.md`](../plans/pairwise-groups.md)):
- the number of members;
- one deterministic ciphertext per member per group, which is linkable within
  the group and unlinkable across groups;
- roles, access rules and join revisions;
- the timing and sizes of changes;
- IP addresses.

## 2. What breaks under federation

Signal's design needs one party that **knows the account** (to issue on its id)
and another, **sharing that party's secret**, that **checks it** without knowing
it. Both are Signal.

In a federation:
- **A foreign home can't verify.** A member's own server is the one that knows
  the account. The group's home is a different operator, and it can't verify a
  MAC credential without the member server's secret. Sharing that secret would
  let the home forge credentials for every account of that server.
- **The home can't issue without learning.** If the home issued credentials
  itself, it would have to learn the account at issuance, unless the attribute
  is blinded. A blinded attribute proves nothing about which account it is.
- **Endorsements have the same split.** The home would issue them and every
  recipient server would verify them, with secrets shared between operators who
  don't trust each other.
- **Recipient sets.** Under the user's decisions the home never takes part in
  delivery, so it doesn't see recipient sets in any design here.

## 3. Candidate designs

**(a) The home issues credentials to remote members.** The member's server
attests the account over federation, and the home issues a KVAC on it. The home
verifies its own credentials, which `lib.rs:29-31` allows, "as long as the
second connection can't be correlated with the first".
- **What the home learns:** every account that holds its credentials, which
  means "this account is in some group of mine". With few groups per home, that
  is close to the membership. Hiding it would need every account to fetch
  credentials from every server.
- **Verdict:** doesn't meet the requirement.

**(b) Each member's server issues, and the home verifies publicly.**
- **What it needs:**
  - a publicly verifiable anonymous credential;
  - a zero-knowledge proof that a ciphertext under the *group's* key holds the
    credential's account (Signal's verifiable encryption);
  - every home trusting every member server's issuer key. That is tolerable:
    a server can always act for its own accounts.
- **The candidates:** BBS/BBS+, Pointcheval–Sanders and CL signatures. All use
  pairing-friendly curves (BLS12-381), not ristretto255.
- **Maturity:**
  - The IETF BBS specification is still an Internet-Draft:
    [draft-irtf-cfrg-bbs-signatures-10](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-10),
    January 2026, informational, an active research-group document. W3C's
    Verifiable Credentials group was still urging the IETF to move it forward in
    [September 2026](https://w3c.github.io/vc-wg/minutes/2026-09-23.html).
  - Blind issuance is a separate draft
    ([bbs-blind-signatures-03](https://ftp.sparcs.org/ietf/draft-irtf-cfrg-bbs-blind-signatures-03.txt)).
  - Verifiable encryption of an identity under a third key, the piece Signal's
    paper adds, isn't part of these drafts. We found no audited Rust
    implementation.
- **Cost:**
  - a new pairing stack next to libsignal's;
  - presentations several times larger and slower than Signal's;
  - our own composition of verifiable encryption.
- **Verdict:** possible in principle; not something to build v1 on.

**(c) Credentials from a key the group's admins hold.**
- With keyed verification, the home would need the admins' secret, so it could
  forge membership.
- With public verification, it falls back to (b)'s maturity problem.
- Its useful core is that the server checks only that a *member key* signed a
  request, without knowing whose key it is. That needs no credential at all. It
  is design (e).

**(d) The literature on federated hidden membership.**
- **Matrix:** room membership is ordinary room state, visible to every
  participating homeserver.
- **MIMI:** the IETF's interoperability work centres on a hub server that sees
  the participant list.
- **MLS:** its own deployments use credentials the delivery service can see.
- We didn't find a deployed or well-reviewed federated system that hides
  membership from the hosting server. This is from known specifications; the
  wider survey was cut short (above) and should be redone before it is cited as
  complete.

**(e) Per-group pseudonymous member keys (recommended).**
- **The keys.** Each member holds, per group, a random signing key pair: its
  pseudonym in that group.
  - Its private key lives in the member's `chatGroups` entry, sealed under the
    account master key, so all the member's devices can use it.
  - Kutup's MLS code used the same device for owners: `owner_id = SHA-256(group-scoped key)`
    (`kutup-chat-proto/src/mls/conversation.rs:342-361`).
- **The plain state the home keeps:** pseudonym public keys, roles, join
  revisions and pending slots. **No AccountRef appears in it.**
- **The encrypted part, for members only:** for each pseudonym, the AccountRef,
  the profile key, and a **binding** signed by one of the account's devices over
  `(group id, pseudonym, AccountRef)`, checked against the account's verified
  manifest.
- **What the home checks.** Every change and every read carries a signature by a
  member's pseudonym. The home checks it, and the pseudonym's role, exactly as
  the plan's server-side acceptance rule requires. The rule still holds, on
  pseudonyms.
- **Adding a member** (Signal's "pending" member, made explicit):
  1. The adder writes a pending slot. Its plain part is the role and
     `H(claimSecret)`; its encrypted part is the AccountRef.
  2. The adder sends the invitee the master key and `claimSecret` over the
     pairwise session.
  3. The invitee claims the slot with a change that reveals `claimSecret` and
     its new pseudonym, signed by that pseudonym, with its encrypted binding.
  4. The home checks the hash; members check that the binding's account is the
     one the slot named.
- **Joining by link:** the requester's pseudonym plus the link password, which
  the home checks as Signal's server does.
- **Duplicates:** the same account added twice is folded by clients, which can
  see the AccountRefs. The home can't.

**Reaching the home without revealing the account: Oblivious HTTP.**
- If a member's own server proxied its group requests as today's federation
  does, it would learn the group id and the home would learn the account.
  Instead we copy [RFC 9458](https://datatracker.ietf.org/doc/html/rfc9458):
  1. The client encrypts each request to the home's published HPKE key.
  2. Its own server relays the opaque blob, learning only the destination
     server.
  3. The home answers through the same relay.
- Members on the home server itself use the same anonymous route, never their
  signed-in session.
- **Building it.** `kutup-crypto` already has HPKE (`hpke-rs`). Mozilla's
  [`ohttp`](https://docs.rs/crate/ohttp/latest) crate implements the protocol,
  though its documentation still warns that it tracks the drafts. We can encode
  RFC 9458's encapsulation with our own HPKE, which keeps "Rust owns the
  formats".

**Sending and calls.**
- Group sends never touch the home. They use sender keys, multi-recipient sealed
  sender and per-member delivery capabilities that carry no group id (§1 of the
  plan).
- The home issues SFU tokens to pseudonyms.

## 4. What each server still learns (design e)

| Who | Learns | Doesn't learn |
| --- | --- | --- |
| The home server | the number of members; one pseudonym per member per group (unlinkable across groups); roles and join revisions; the timing and sizes of changes and reads; the relay server each request came through; IPs of members on the home itself | any member's account, unless correlated through timing or IPs |
| A member's own server | that its user talks to home H (relayed blobs), with timing and sizes; that its user receives sealed mail under one more capability; which of its users share one multi-recipient send from one origin (so that they share *some* group) | the group id, the other members, the user's role |
| The sender's server | that someone (anonymous route) sent to some destinations | who sent, or to which group |

**Compared with Signal's server**, which sees one ciphertext per member, roles,
timing, IPs and the recipient set of each multi-recipient send, design (e)
leaks about the same to the home and spreads the rest over servers that each
see less.

**Leaks no design here removes:**
- traffic analysis across cooperating servers (timing of fan-out);
- IP addresses, unless the client uses a network-level anonymiser;
- that group's own members see each other, which is the point.

## 5. Recommendation

1. **Adopt design (e)** for groups v1: pseudonymous member keys, encrypted
   bindings, Oblivious-HTTP relaying through the member's own server, and
   delivery capabilities without group ids.
2. **Do not adopt zkgroup**, in either form:
   - keyed-verification credentials across federated servers ((a), (c)) either
     leak membership to the issuer or need a shared secret between operators;
   - publicly verifiable credentials (b) aren't standardised or mature in Rust,
     and the verifiable-encryption piece would be ours to compose.
3. **Revisit (b)** if BBS becomes an RFC with an audited Rust implementation and
   a verifiable-encryption extension. Design (e) leaves room: a member entry is
   one field.

**What design (e) adds to the group plan:**
- Third session, about 4–6 days: pseudonym keys and bindings, claims, the
  relay client.
- Second session, about 4–6 days: the pseudonym ACL, the HPKE gateway and the
  relay route, link joins by pseudonym.
- It replaces the plain-AccountRef ACL and needs no new cryptographic library.
