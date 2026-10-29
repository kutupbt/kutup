# Organizations, following Proton

Status: proposal, 2026-10-29, for the user's review. Nothing is built.

- **Need (user):** two accounts on one custom mail domain, e.g.
  `a@mail.t.co` for account 1 and `b@mail.t.co` for account 2. Today a
  domain has one holder, an account ([`mail-custom-domains.md`](mail-custom-domains.md)
  §1, "one holder at a time"), and organizations were deferred to Phase E
  "as Proton's" (that note; [`mail-groups.md`](mail-groups.md), "Storage
  owner"; `roadmap.md`, Mail E).
- **Copies:** Proton WebClients (`kutup-references/WebClients`, read only).
  Paths below are relative to its root.
- Proton's server isn't public. Where only the server would answer, this
  note says so and proposes Kutup's rule.
- Related: [`mail-address-keys.md`](mail-address-keys.md),
  [`account-ids.md`](account-ids.md), [`account-identity-key.md`](account-identity-key.md),
  [`settings-registry.md`](settings-registry.md), [`wipe-unification.md`](wipe-unification.md),
  [`opaque.md`](opaque.md) (admin reset).

## Summary

- An **organization** is a permanent random id with members and roles. It
  owns custom domains; an account that adds a domain alone gets an
  organization of one, as a Proton Mail Plus user has an organization.
- **Every member is private** in v1 (Proton's "private" member): the
  member's client makes and holds all its keys, administrators can't read
  or reset anything. **No organization key** in v1. Managed (non-private)
  members, with Proton's consent flow, can come later as an addition.
- **Administrators make addresses on the organization's domains for
  members** (Proton's `POST addresses {MemberID, …}` for a private member):
  the row comes without a key, and the member's own client makes the key
  and signs its key list with the member's authority, as for any address.
- **Wipe:** no crypto format changes. Only schema: domains keyed by
  organization id, and organization-scoped settings. Both are cheap now and a
  data migration later, not a wipe.

## What Proton has

### The model

- **`Organization`** (`packages/shared/lib/interfaces/Organization.ts:15-72`):
  `ID`, `Name`, `State` (disabled, active, delinquent), quota triples
  `MaxX/UsedX/BonusX` for domains, addresses, members, space and more,
  `HasKeys`, `RequiresKey`, `TwoFactorRequired`, `Features` (bit 1:
  catch-all). Settings (`:87-105`): `ShowName`, `LogoID`, password policies.
- **`UserOrganization`** (`Organization.ts:118-128`): an account may appear
  in several organizations (`IsPrimary`), with `MemberRole` and
  `AddressIDs` in each.
- **`Member`** (`interfaces/Member.ts:131-157`): `Role`, `Private`, `Type`,
  `State`, `AccessToOrgKey`, `Keys`, `MaxSpace`/`UsedSpace`, `Addresses`,
  `Unprivatization`.
- **Enums** (`packages/shared/lib/constants.ts`):
  - `MEMBER_ROLE` (`:622`): none 0, member 1, admin 2. Delegated roles on
    top: Owner, User Admin, Security Admin (`interfaces/OrganizationRole.ts:1-46`),
    with permission strings like `account.user.delete`, `account.domain.*`
    (`interfaces/UserPermission.ts:16-50`).
  - `MEMBER_PRIVATE` (`:617`): readable 0 (the organization key opens the
    member's keys), unreadable 1 (private).
  - `MEMBER_TYPE` (`:563`): PROTON 0 (an existing account that was
    invited), MANAGED 1 (created by the organization).
  - `MEMBER_STATE` (`Member.ts:14`): disabled, enabled, invited.

### The organization key

- **Passwordless** (current): `generatePasswordlessOrganizationKey`
  (`packages/shared/lib/keys/organizationKeys.ts:84-106`), an OpenPGP key
  locked by a random token encrypted and signed to the creating admin's user
  key. Other admins get the token re-encrypted to them, sent with the role
  change (`PUT core/v4/members/{id}/role {OrganizationKeyActivation |
  OrganizationKeyInvitation}`, `api/members.ts:208-225`); a private admin
  accepts and re-encrypts it to itself
  (`packages/account/organizationKey/actions.ts:969-1062`). An admin
  address signs the key's fingerprint ("organization identity",
  `organizationKeys.ts:485-530`).
- **What it encrypts:** for each **non-private** member, a second copy of
  the member's user key, locked by a member token encrypted to the
  organization key (`keys/memberToken.ts:30-47`, `keys/memberKeys.ts:76-131`),
  plus organization signatures on address-key tokens and the group address
  keys' tokens (`api/organization.ts:68-72`). Private members have nothing
  under it.
- **What it enables:** for non-private members only, "Sign in as" the member
  (`POST core/v4/members/{id}/auth`, `organizationKey/memberAccessAction.ts:47-80`)
  and "Change password" with their data kept (`memberPasswordAction.ts:21-98`).
  The UI says of private members: "Admins can't access the data of private
  users and can't reset their password" (`packages/account/members/actions.ts:82-84`).
- **Losing it:** resetting the key privatizes every non-private member,
  rotates, then asks each to consent again
  (`organizationKey/resetOrganizationKey.ts:28-38`).

### Members

- **Created by the organization** (`packages/account/members/actions.ts:593-877`,
  `POST core/v4/members {Name, Private, MaxSpace, …}`), then addresses
  (`POST core/v4/members/{id}/addresses`). Modes (`Member.ts:43`): a
  password the admin sets, a login link, or an emailed invitation.
  - Non-private: the admin's client generates the member's user and address
    keys (`setupMemberKeys`, `memberKeys.ts:60-150`); needs the
    organization key.
  - Private: the member is created with addresses but **no keys**; the
    member generates them at first sign-in
    (`account/addressKeys/createAddressKeys.ts:110-117`).
- **Inviting an existing account** (`POST core/v4/members/invitations
  {Email, MaxSpace, …}`, `api/members.ts:283-305`; the invitee's
  `POST core/v4/users/invitations/{id}/accept|reject`, `api/user.ts:137-155`).
  The invitee keeps their account and addresses. The accept screen refuses
  some accounts (`interfaces/PendingInvitation.ts`, `HasOrgWithMembers`,
  `HasCustomDomains`, …): "Accounts with custom domains cannot join a family
  plan" (`PendingInvitationModalErrors.tsx:70-94`).
- **Unprivatization** (private → non-private) needs the member's consent:
  the admin signs a request with the organization key (`POST
  core/v4/members/{id}/unprivatize`); the member sees "An administrator of
  {org} wants to enable admin access for your account" and "If you ever lose
  access to your credentials, your organization's administrators will be
  able to reset your password" (`MemberUnprivatizationModal.tsx:104-136`),
  checks the admin's and organization key's signatures, and on accept
  encrypts a copy of its keys to the organization key
  (`keys/unprivatization.ts:261-353`).
- **Admins see** members, their addresses, roles, storage use and last
  activity (`MembersTable.tsx:86-389`), never a private member's data.

### Domains, addresses, catch-all

- Domain routes carry no organization in the path (`api/domains.ts:1-50`):
  the session's organization owns them. Domain limits are the
  organization's (`MaxDomains`).
- **Addresses for any member:** `POST core/v4/addresses {MemberID, Local,
  Domain, DisplayName}` (`api/addresses.ts:32-36`). For a private member the
  address is made without keys and the member generates them; only the
  member may (`memberKeys.ts:171-197`).
- **Catch-all** on any address on the domain (`PUT domains/{id}/catchall`),
  gated by the organization's feature bit.

### Removal and leaving

- **Created members are deleted:** "This will permanently delete the data
  and all email addresses associated with this user", confirmed by typing
  the name (`SubUserDeleteModal.tsx:55-79`).
- **Invited members are removed** ("Remove", not "Delete",
  `MemberActions.tsx:57-59`) and go back to a plan of their own
  (`UserRemoveModal.tsx:55-79`). A member leaves with `DELETE
  core/v4/organizations/membership` (`api/organization.ts:187`,
  `LeaveFamilyModal.tsx`).
- What happens to an invited member's addresses on the organization's
  domains is **server-only**; the client doesn't show it.

## Proposal

### 1. Data model

```
organizations (
  id uuid,                    -- permanent, random
  name text,                  -- changeable attribute, shown to members only
  state smallint,             -- Proton's: 0 disabled, 1 active
  created_at, disabled_at timestamptz
)

organization_members (
  organization_id uuid,
  account_id uuid,            -- users.id
  role text,                  -- 'owner' | 'admin' | 'member'
  state smallint,             -- Proton's MEMBER_STATE: 0 disabled, 1 enabled, 2 invited
  created_by_org boolean,     -- Proton's MEMBER_TYPE: MANAGED vs PROTON
  invited_by uuid, invited_at, joined_at timestamptz,
  PRIMARY KEY (organization_id, account_id)
)
UNIQUE (account_id) WHERE state IN (1, 2)        -- one organization per account
-- at least one enabled owner per organization (checked in the transaction)

mail_domains.organization_id uuid   -- replaces mail_domains.user_id
UNIQUE (organization_id, name)
UNIQUE (name) WHERE state IN (1, 2)              -- unchanged: one holder
```

- **Roles** are Proton's legacy two plus its Owner: `owner` (everything,
  deletes the organization, makes owners), `admin` (members, invitations,
  addresses, domains, catch-all), `member`. Proton's delegated permission
  strings are left out: three fixed roles cover the need, and a permission
  table can come later without changing the rows.
- **One organization per account.** Proton's model allows several
  (`UserOrganization`), but its accept screen refuses accounts already in one
  with members or domains. Kutup keeps the simpler rule in v1; the partial
  unique index can be dropped later without data change.
- **No `private` column.** Every member is private (§3); a column only
  appears when managed members do. No shim.
- **Organization of one.** The first domain an account adds creates an
  organization with the account as its owner, named after its username. It
  shows as "Organization" in settings only once the owner invites someone.
  - **Why:** Proton's domains belong to the session's organization
    (`api/domains.ts`, `Organization.MaxDomains`), so a single Proton user
    with a domain has one too, there is one ownership path in the domain code, and
    inviting someone needs no conversion of the domain.
  - The alternative, domains per user plus a move into an organization when
    one is made, keeps two ownership paths and a transfer between them.
- **Addresses stay owned by the account** (`mail_addresses.user_id`): the
  member's mailbox, keys and key list are the member's. The organization's
  control is through the domain (`domain_id → organization_id`).
- **Mail groups:** `mail_groups.storage_owner` gains `organization`, and
  groups on an organization's domains are a later slice (§9, O6).
  [`mail-custom-domains.md`](mail-custom-domains.md) §0 keeps them off
  custom domains until then.

### 2. Addresses for members

- **Who makes them:** owners and admins, for any enabled member, on a usable
  domain of the organization (`verified` or `warn`), as Proton's
  `POST addresses {MemberID}`. Route: `POST /api/orgs/{id}/members/{account}/addresses
  {local, domainId}`. A member can't make addresses on the organization's
  domains alone (Proton's members can't either).
- **No key from the admin.** The row is created `active` with no key. The
  member's Account shell already makes a first key for every address that has
  neither key nor key list ([`mail-address-keys.md`](mail-address-keys.md),
  "A first key only over nothing"), sealed under the member's master key and
  listed in a `MailKeyListV1` signed by the member's authority. Until then
  the address shows "Missing keys", as Proton's, and the RCPT hook refuses
  it as an address without a key (unchanged).
- **So the admin never holds a member's key,** and recipients who pinned the
  member's account trust the address through that account.
- **Address states and folding** are those of custom domains (lowercase
  only, `freed` when ended). The canonical form is
  `kutup_crypto::mail_address::canonical`, unchanged.
- **Reassigning** an address from one member to another is not offered.
  Admins remove it (it goes `freed`, §5) and make it again for the other
  member, who makes a new key; correspondents see a different account id,
  a different person, never inherited trust (custom domains §8).
- **Catch-all:** any `active` address on the domain, of any member, set by
  owners and admins. The cap per domain per day is unchanged.
- **Display name and sending** are the member's, as for any address. The
  send checks (custom domains §5) add one: the domain's organization must
  be `active` and the member `enabled`.

### 3. Organization key and managed members: not in v1

- **What a Kutup organization key would have to encrypt:** a non-private
  member's **master key**, the one root of the account (W6). That opens
  everything: Drive, Chat history backups, Pass vaults, Calendar, Photos,
  Mail. Proton's user key is the same kind of root, so its "non-private"
  means the same reach.
- **Why not now:**
  - The need (two accounts on one domain) doesn't require it.
  - Proton's own default for invited accounts is private, and a private
    member can't be made readable without consent.
  - It adds a second way into every account's data, a key that must be
    rotated with consent on loss (`resetOrganizationKey.ts`), and an
    admin "sign in as" that Kutup's E2EE claim would have to describe.
- **Later, as an addition (no wipe):** an organization key pair (X-Wing,
  like the account's HPKE key, [`pq-shares.md`](pq-shares.md)), held by
  owners as shares sealed to their account keys, as mail group keys are
  ([`mail-groups.md`](mail-groups.md)). A member who consents (Proton's
  unprivatization text, verified signatures) seals its master key to it as
  a new account-envelope purpose. Labels would follow the registry grammar,
  e.g. `kutup/org/member-escrow/v1\0`. With W6's `mk_gen` a rotated master
  key re-seals. Nothing in v1 has to change for it.
- **Consequences in v1, stated in the UI** (Proton's text): "Admins can't
  access the data of private users and can't reset their password." A
  member who loses password and recovery phrase loses their data; the
  server administrator's destructive reset ([`opaque.md`](opaque.md), "Admin
  temporary passwords") is still there, but organization admins don't get it.

### 4. Joining

**Inviting an existing account** (Proton's `members/invitations`), first:
- An owner or admin invites a username on this server
  (`POST /api/orgs/{id}/invitations {username}`); the server resolves it to
  the account id and stores the row `invited` against that id, so a rename
  in between changes nothing.
- The invitee sees a banner in Account and accepts or declines
  (`POST /api/orgs/invitations/{id}/accept|decline`), as
  `PendingInvitationModal`. The screen names the organization, the inviting
  admin, and what admins can and can't do (Proton's private text).
- **Refused at accept** (Proton's `AcceptInvitationValidation`, adapted):
  the account is already in an organization with other members; or its
  organization of one holds domains ("Remove your domains, or invite the
  other person into your organization instead"). An organization of one
  without domains is dissolved on accept.
- Invitations expire (a setting, 14 days), and the invitee may block an
  organization's further invitations.
- Only accounts on this server. Organizations don't federate (§6).

**Creating accounts for the organization** (Proton's MANAGED, private), second:
- An owner or admin creates an account with a username and a temporary
  password, through the existing admin-reset registration path
  ([`opaque.md`](opaque.md): a fresh key binding with a grant, issued from
  the admin's reauth). The member signs in, makes all its own keys and
  recovery phrase, and sets its password, as an admin-created account does
  today. The admin never sees a key.
- `created_by_org` marks it: the organization may disable, enable and delete
  it (Proton's MANAGED-only actions); it can't leave on its own while the
  organization exists (Kutup's rule; Proton's client offers leaving only
  to invited family members, `LeaveFamilyModal.tsx`). Whether to
  ship this at all is open question 3.
- Registration's own gates (registration codes, the site's sign-up mode)
  don't apply, but a setting caps it (§7).

### 5. Leaving and removal

As Proton, with the server-only parts decided by custom domains §8:
- **An invited member leaves, or is removed** (`DELETE /api/orgs/{id}/members/{account}`,
  "Remove"):
  - their addresses on the organization's domains go `freed`: the key list
    drops them, outside lookup and Autocrypt stop serving them, forwardings
    from them and a catch-all pointing at them end;
  - **their mail stays in their own mailbox** and still opens (the keys
    stay, sealed under their master key), as their account is theirs;
  - their username address and everything else are untouched;
  - the organization may make the freed local part again for someone else
    at once (open question 4), who starts clean.
- **A created member is deleted** ("Delete", typing the username to confirm,
  Proton's text): the account is deleted as any account is, freeing its
  addresses.
- **The last owner** can't leave or be removed; they delete the organization
  or make another owner first.
- **Deleting the organization** needs no other members (Kutup's rule;
  Proton's server decides this and the client doesn't show it). Its domains are removed as custom domains §8
  says ("all the addresses associated with it will be disabled").
- **Disabling a member** (Proton's disable): their organization addresses
  refuse mail at RCPT and can't send; nothing is freed.
- Each of these is an account security event for the member (`orgJoined`,
  `orgLeft`, `orgRemoved`; the CHECK list on `account_security_events.kind`
  grows in the same migration).

### 6. The other apps and federation

- **Federation:** an organization is local to one server; members are
  accounts on it. Addresses on its domains are ordinary Kutup addresses to
  other servers: key lookup, signed key lists, pins on the member's
  `AccountRef`. Nothing in the federation protocol changes.
- **Chat:** no organization badge or name in Chat, Mail or Drive outside the
  organization. Signal has none, and a server-asserted organization name is
  a phishing label (anyone can name one "Acme Bank"). A person stays their
  account; members see the organization in Account only.
- **Drive:** organization shared drives are out of scope. A shared space
  would be its own design (a collection shared to the members, owned by the
  organization's storage). Proton's organization key holds members' keys,
  not a shared drive, so there is nothing to copy here.
- **Calendar and Contacts:** no organization directory or free/busy in v1.
  An address on an organization domain can own a calendar like any address
  (W4 moves calendar keys to account-level keys anyway).
- **Pass:** no organization vaults in v1 (Proton Pass for Business has
  them; a later note, once there is a sharing design).
- **Storage:** stays one pool per account. Proton allocates organization
  space to members (`MaxSpace`); Kutup has no billing, so the server admin's
  per-account settings already do it.

### 7. Limits: settings, not plans

Kutup has no billing; each limit is a registry setting
([`settings-registry.md`](settings-registry.md)), site-wide with a value per
organization. The registry gains an organization scope:
`organization_setting_overrides (organization_id, key, value)` and
`setting.load_for_org(...)`, edited on the organization's admin page. The
per-account `mail_domain_overrides` table goes (its values become
organization or account registry values).

| Setting | Default |
| --- | --- |
| Organizations: `everyone` / `admins approve` / `off` | as custom domains' (`everyone` on kutup.dev) |
| Members per organization | 10 |
| Domains per organization (was per account) | 3 |
| Addresses on the organization's domains | 10 per organization |
| Accounts an organization may create | 0 until open question 3 is answered |
| Pending invitations per organization | 20 |
| Invitations sent per organization per day | 20 |
| Invitation lifetime | 14 days |
| Catch-all, its cap | as custom domains' |

Rate limits (registry): invitation sends, accepts and address creation per
account and per organization.

## Wipe sensitivity

**No crypto format changes**, so nothing here forces a wipe:
- address keys bind the address and fingerprint and sit under the member's
  master key (`crates/kutup-crypto/src/mail_key.rs`);
- key lists are signed by the member's authority;
- DKIM targets use the domain id, which doesn't change hands
  ([`mail-custom-domains.md`](mail-custom-domains.md) §4);
- nothing binds an organization, a domain's holder or an organization name.

**Land before the wipe because they are cheap now** (schema only, in the
migration squash):
1. `mail_domains.organization_id` in place of `user_id`, with
   `UNIQUE (organization_id, name)` and the held index unchanged; the verify
   code reused per organization.
2. `organizations` and `organization_members` (even if the routes come
   later), so domains have their owner from the first row.
3. The organization scope in the settings registry, and
   `mail_domain_overrides` gone.

After the wipe each of these is a data migration (an organization of one per
domain-holding account), not a wipe: annoying, not dangerous.

**Can follow later without a wipe:** invitations, created accounts, roles
beyond three, several organizations per account, mail groups on organization
domains, the organization key and managed members (§3), organization
vaults or drives, an organization directory.

## Abuse and security

- **Admins can't read members' mail or data:** no admin-side key, no
  "sign in as", no password reset with data kept. A live test asserts the
  server never stores a key envelope for an organization address that the
  member's client didn't upload.
- **Admins do control routing,** as any domain owner does (Proton the
  same): they can free a member's organization address and make it again
  for someone else, or move MX. Correspondents see a different account id,
  and the member keeps the mail already received. The member's username
  address is out of the organization's reach.
- **Domain transfer rules hold** (custom domains §2, §8), with the holder
  being the organization: proof twice an hour apart, the security notice to
  the organization's owners, the addresses freed.
- **No unwanted membership:** an invitation needs the invitee's accept, and
  can be blocked. Organization names aren't shown outside (§6).
- **Server administrators** see organizations, members and domains in the
  admin console, can disable an organization (its domains stop as an
  `inactive` domain does), and set its limits.
- **Two-factor:** Proton's "require 2FA for members" is a later addition
  (an organization setting the sign-in check reads).

## Phasing

Each slice is its own PR with its live and browser tests.

| Slice | What | Tests |
| --- | --- | --- |
| **O1 server** (before the wipe) | tables; organization of one on the first domain; domains keyed by organization; registry organization scope; `/api/orgs` read routes | live: an account adds a domain and owns its organization of one; limits read from the organization |
| **O2 server** | invitations (send, accept, decline, expire, block), roles, leave and removal with addresses freed, admin-made addresses without keys, catch-all on any member's address, security events | live (mail gate with CoreDNS): account 1 verifies `mail.t.co`, invites account 2, makes `b@mail.t.co`; account 2's client makes its key; both receive and send with `d=mail.t.co`; account 2 leaves, `b@` refuses at RCPT, account 2 still opens old mail; a non-admin is refused every admin route |
| **O3 web** (third session) | Account → Organization: Proton's "Users and addresses" (invite user, add address, roles, remove), the invitation banner and accept screen, the wizard's Addresses step pointing at it; admin console organizations | browser: two accounts, invitation, address, a message each way, leave |
| **O4 CLI** | `kutup org` (show, invite, accept, addresses, leave) | CLI live tests in the mail gate |
| **O5** (if open question 3 is yes) | accounts created by the organization, disable, delete | live and browser |
| **O6** | mail groups on organization domains, storage owner `organization` | the mail groups suite |

## Open questions

1. **Can organization admins ever get into members' accounts?** Proton
   allows it for "non-private" members, with the member's consent, so the
   admin can reset a forgotten password. That also lets admins read
   everything in the account. *Recommendation:* not in v1; every member is
   private. It can be added later without a wipe.
2. **Should someone with their own domain automatically have an
   "organization of one"?** *Recommendation:* yes, as Proton does: one way
   to own domains, and inviting someone later needs no conversion.
3. **Should organizations be able to create accounts for people**, or only
   invite people who already have one? Created accounts can be disabled or
   deleted by the organization (Proton's "managed" users). *Recommendation:*
   invitations first (O2); creating accounts as a separate slice (O5), off
   by default per server.
4. **When a member leaves, may the organization give their address to
   someone else right away?** *Recommendation:* yes, as Proton: the domain is
   the organization's, the departing member keeps the mail already received,
   and correspondents see a new person. A waiting period could be an admin
   setting later.
5. **One organization per account?** Proton's data model allows several,
   but its screens refuse joining while you run one with members or
   domains. *Recommendation:* one per account in v1; allowing more later
   needs no data change.
