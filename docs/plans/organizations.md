# Organizations, following Proton

Status: proposal, revised 2026-10-29 after the user's answers (Decisions).
Nothing is built.

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
  [`settings-registry.md`](settings-registry.md), [`wipe-unification.md`](wipe-unification.md)
  (W1, W6), the W6 build note `w6-key-hierarchy.md` (branch
  `wipe/w6-key-hierarchy`: `MasterKeyGeneration`, the label registry),
  [`pq-shares.md`](pq-shares.md), [`opaque.md`](opaque.md) (admin reset).

## Decisions (the user, 2026-10-29: "follow Proton" on each)

1. **Admin access with the member's consent, as Proton:** managed
   (non-private) members and an organization key, designed now (§3).
2. **Organization of one:** adding a domain makes the account an
   organization's owner.
3. **Joining:** both, as Proton: accounts the organization creates, and
   invitations of existing accounts (§4).
4. **Address reuse after a member leaves:** as Proton (§5).
5. **One organization per account,** as Proton's screens enforce.

## Summary

- An **organization** is a permanent random id with members and roles. It
  owns custom domains.
- **Two kinds of member, as Proton's `MEMBER_PRIVATE`:**
  - **private:** the member alone holds their keys; admins can't read,
    reset or sign in;
  - **managed:** a copy of the member's **master key** is sealed to the
    organization key, so admins can reset the password with data kept and
    sign in as the member, and can read **every app's data**.
- **Defaults, as Proton:** an account the organization creates is managed
  (`SubUserCreateModal.tsx:162`, `private: false`), with a private toggle;
  an invited existing account is **private**, and becomes managed only if it
  consents to an admin's request.
- **The organization key** is an X-Wing key pair. Owners and admins hold its
  private part under their own master keys (a new account-envelope purpose);
  a new admin receives it sealed to their account key and signed by the
  granting admin.
- **Wipe:** the schema (domains keyed by organization), and the new formats'
  numbers and labels, land before the wipe. No existing format changes
  beyond W6's master-key generation, which W6 already brings.

## What Proton has

### The model

- **`Organization`** (`packages/shared/lib/interfaces/Organization.ts:15-72`):
  `ID`, `Name`, `State` (disabled, active, delinquent), quota triples
  `MaxX/UsedX/BonusX` for domains, addresses, members, space and more,
  `HasKeys`, `RequiresKey`, `TwoFactorRequired`, `Features` (bit 1:
  catch-all). Settings (`:87-105`): `ShowName`, `LogoID`, password policies.
- **`UserOrganization`** (`Organization.ts:118-128`): the data model allows
  several organizations per account (`IsPrimary`); the accept screen refuses
  accounts already running one (`interfaces/PendingInvitation.ts`,
  `HasOrgWithMembers`, `HasCustomDomains`).
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
  - `MEMBER_ORG_KEY_STATE` (`Member.ts:20-29`): no key, active, missing,
    pending.

### The organization key

- **Passwordless** (current): `generatePasswordlessOrganizationKey`
  (`packages/shared/lib/keys/organizationKeys.ts:84-106`), an OpenPGP key
  locked by a random token encrypted and signed to the creating admin's user
  key. Setup says "All administrators will get access to the key"
  (`SetupOrganizationModal.tsx:155-170`).
- **A new admin gets it** with the role change (`PUT core/v4/members/{id}/role
  {OrganizationKeyActivation | OrganizationKeyInvitation}`,
  `api/members.ts:208-225`):
  - a managed admin: the token re-encrypted to their user key
    (`generatePublicMemberActivation`, `organizationKeys.ts:465-483`);
  - a private admin: the token encrypted to their verified address key and
    signed by the inviting admin (`generatePrivateMemberInvitation`,
    `:439-463`); they verify the signature, re-encrypt to their own user key
    and activate (`PUT core/v4/organizations/keys/activate`,
    `packages/account/organizationKey/actions.ts:969-1062`);
  - a private member can be promoted only after their first sign-in
    (`actions.ts:78-80`).
- **The organization's identity:** an admin address signs the key's
  fingerprint (`organizationKeys.ts:485-530`), and members check it before
  consenting.
- **What it encrypts:** for each managed member, a second copy of the
  member's user key, locked by a member token encrypted to the organization
  key (`keys/memberToken.ts:30-47`, `keys/memberKeys.ts:76-131`), plus
  organization signatures on address-key tokens and group address keys
  (`api/organization.ts:68-72`). Private members have nothing under it.
- **What it enables, for managed members only, owners only**
  (`components/containers/members/MemberActions.tsx:96-190`):
  - **Sign in as** (`POST core/v4/members/{id}/auth`,
    `organizationKey/memberAccessAction.ts:47-80`): "You can now access and
    manage the account as an administrator" (`LoginMemberModal.tsx:46-49`);
  - **Change password** with data kept, which also turns off the member's
    two-factor (`memberPasswordAction.ts:21-98`, `:83`).
- **Losing or resetting it** (`organizationKey/resetOrganizationKey.ts:28-38`):
  privatize every managed member, rotate, then ask each to consent again:
  "Your account was temporarily made private while your organization key was
  reset. Accept the request to restore it."

### Members

- **Created by the organization** (`packages/account/members/actions.ts:593-877`,
  `POST core/v4/members {Name, Private, MaxSpace, …}`), then addresses
  (`POST core/v4/members/{id}/addresses`). Modes (`Member.ts:43`): a
  password the admin sets, a login link, or an emailed invitation.
  - Managed (the default): the admin's client generates the member's user
    and address keys (`setupMemberKeys`, `memberKeys.ts:60-150`); this needs
    the organization key ("Organization key must be activated to create
    non-private users", `actions.ts:678-683`).
  - Private: the member is created with addresses but **no keys**; the
    member generates them at first sign-in
    (`account/addressKeys/createAddressKeys.ts:110-117`). "Admins can't
    access the data of private users and can't reset their password"
    (`actions.ts:82-84`).
- **Inviting an existing account** (`POST core/v4/members/invitations
  {Email, MaxSpace, …}`, `api/members.ts:283-305`; the invitee's
  `POST core/v4/users/invitations/{id}/accept|reject`, `api/user.ts:137-155`).
  The invitee keeps their account and addresses; the payload has no
  `Private` field.
- **Unprivatization** (private → managed) needs consent:
  - the admin signs a request (`POST core/v4/members/{id}/unprivatize`,
    `members/unprivatizeActions.ts:79-123`);
  - the member sees "An administrator of {org} wants to enable admin access
    for your account" (`UnprivatizationRequestTopBanner.tsx:55`) and "If you
    ever lose access to your credentials, your organization's administrators
    will be able to reset your password and restore access to your account",
    with a reject link (`MemberUnprivatizationModal.tsx:104-136`);
  - the client checks the admin's keys, the organization key's fingerprint
    signature and the request's signature (`keys/unprivatization.ts:261-316`),
    then encrypts a copy of its keys to the organization key (`:318-353`);
  - the admin's client finalizes it (`:446-543`).
- **Privatizing** (managed → private): `PUT core/v4/members/{id}/privatize`
  (`api/members.ts:266-275`), by an admin; the client has no member-side
  flow for it.
- **Admins see** members, their addresses, roles, storage use and last
  activity (`MembersTable.tsx:86-389`).

### Domains, addresses, catch-all

- Domain routes carry no organization in the path (`api/domains.ts:1-50`):
  the session's organization owns them, within `MaxDomains`.
- **Addresses for any member:** `POST core/v4/addresses {MemberID, Local,
  Domain, DisplayName}` (`api/addresses.ts:32-36`). For a managed member
  the admin's client makes the keys; for a private one the member does
  (`memberKeys.ts:171-197`, `components/containers/addresses/helper.ts:106`).
- **Deleting an address on a custom domain** is open to admins at any time
  (`addresses/helper.ts:146`, `adminCanDeleteCustom`): "Delete address?…
  you will no longer be able to send or receive emails using this address"
  (`DeleteAddressPrompt.tsx:57-63`). Only addresses on Proton's own domains
  are "permanent": "Once deleted, this address … can't be used again by
  anyone else", once a year (`:47-55`). The client expects custom-domain
  addresses to be reused: "Disabled addresses might now belong to other users
  … who reused them" (`account/publicKeys/verificationPreferences.ts:43`).
- **Catch-all** on any address on the domain (`PUT domains/{id}/catchall`).

### Removal and leaving

- **Created members are deleted:** "This will permanently delete the data
  and all email addresses associated with this user", confirmed by typing
  the name (`SubUserDeleteModal.tsx:55-79`).
- **Invited members are removed** ("Remove", `MemberActions.tsx:57-59`) and
  go back to a plan of their own (`UserRemoveModal.tsx:55-79`). A member
  leaves with `DELETE core/v4/organizations/membership`
  (`api/organization.ts:187`).
- What happens to an invited member's addresses on the organization's
  domains is **server-only**.

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
  state smallint,             -- MEMBER_STATE: 0 disabled, 1 enabled, 2 invited
  created_by_org boolean,     -- MEMBER_TYPE: MANAGED (true) vs PROTON
  private boolean,            -- MEMBER_PRIVATE
  org_key_state smallint,     -- MEMBER_ORG_KEY_STATE (admins): 0 none, 1 active, 2 missing, 3 pending
  invited_by uuid, invited_at, joined_at timestamptz,
  PRIMARY KEY (organization_id, account_id)
)
UNIQUE (account_id) WHERE state IN (1, 2)        -- one organization per account

organization_keys (id, organization_id, public_key, certificate, state, created_at)
                                                 -- state: active | retired
organization_key_shares (key_id, account_id, sealed_share NULL, envelope NULL, granted_by)
                                                 -- pending: sealed_share; active: envelope
organization_member_escrows (organization_id, account_id, key_id, mk_generation, sealed)
organization_access_requests (organization_id, account_id, request, created_at)

mail_domains.organization_id uuid                -- replaces mail_domains.user_id
UNIQUE (organization_id, name)
UNIQUE (name) WHERE state IN (1, 2)              -- unchanged: one holder
```

- **Roles:** `owner` (everything, deletes the organization, makes owners,
  "sign in as" and password reset, as Proton's owner-only actions), `admin`
  (members, invitations, addresses, domains, catch-all, access requests),
  `member`. Owners and admins hold the organization key. Proton's delegated
  permission strings are left out; a permission table can come later
  without changing these rows. At least one enabled owner always.
- **One organization per account** (the partial unique index).
- **Organization of one:** the first domain an account adds creates an
  organization with the account as its owner, named after its username,
  with no key until someone else joins as managed. Proton's domains belong
  to the session's organization (`api/domains.ts`, `Organization.MaxDomains`),
  so a single Proton user with a domain has one too, and there is one
  ownership path in the domain code.
- **Addresses stay owned by the account** (`mail_addresses.user_id`); the
  organization's control is through the domain (`domain_id → organization_id`).
- **Mail groups:** `mail_groups.storage_owner` gains `organization` in a
  later slice (§9, O8).

### 2. Addresses for members

- **Who makes them:** owners and admins, for any enabled member, on a usable
  domain of the organization (`verified` or `warn`), as Proton's
  `POST addresses {MemberID}`: `POST /api/orgs/{id}/members/{account}/addresses
  {local, domainId}`. Members don't make addresses on the organization's
  domains themselves (Proton's can't either).
- **Keys, by kind of member:**
  - **managed:** the admin's client opens the member's master key from the
    escrow (§3), makes the address key, seals it under that master key
    (purpose `MailAddressPrivateKey`) and signs the next key list with the
    authority the master key derives, exactly as the member's own client
    would;
  - **private:** the row comes without a key ("Missing keys", as Proton's),
    and the member's Account shell makes it ([`mail-address-keys.md`](mail-address-keys.md),
    "A first key only over nothing"). The RCPT hook refuses an address
    without a key, as today.
- **Either way the key list is signed by the member's authority,** so
  correspondents trust the address through the member's account and its
  pins.
- **Address states and folding** are those of custom domains (lowercase,
  `freed` when ended); the canonical form is
  `kutup_crypto::mail_address::canonical`.
- **Catch-all:** any `active` address on the domain, of any member, set by
  owners and admins.
- **Sending:** the send checks (custom domains §5) add one: the domain's
  organization is `active` and the member `enabled`.

### 3. The organization key and managed members

#### What a managed member gives the organization

The escrowed secret is the member's **master key**, the one root of the
account (W6). Proton's user key has the same reach. With it, an owner or
admin can:
- **read every app's data:** Drive and Photos, Mail, Calendar, Contacts,
  Pass vaults, Office documents, Chat history backups;
- **act as the member:** sign the member's key lists and manifests, so add
  a device or a key in their name;
- **reset the password with data kept**, and **sign in as the member**
  (owners only, as Proton).

The UI says so in plain words wherever it matters (§3.3, §4). Correspondents
can't tell a managed account from a private one, as at Proton.

#### Formats (kutup-crypto, all post-quantum where Kutup is)

- **Organization key:** an X-Wing key pair (the HPKE suite of
  [`pq-shares.md`](pq-shares.md)), its seed random, made in the creating
  owner's browser. Its id is a hash of the public key under
  `kutup/org/key-id/v1\0`.
- **`OrganizationKeyCertificateV1`** (`kutup/org/key-certificate/v1\0`):
  organization id, key id, the X-Wing public key, issued at, and the signing
  admin's account ref, incarnation and authority key id; Ed25519 signature
  by that admin's account authority. It is Proton's fingerprint signature
  (`organizationKeys.ts:485-530`); members check it against their pins of
  that admin before consenting.
- **The admin's own copy:** the seed under the admin's master key as an
  account envelope with a **new purpose, `OrganizationPrivateKey = 7`**
  (purpose 3 stays reserved after W6), object id = the key id, carrying the
  master-key generation as every envelope does after W6. If W1's
  `AccountRecordV1` replaces purposes with record types, this becomes that
  record type instead; either way its number is fixed with the wipe set.
- **`OrganizationKeyShareV1`** (`kutup/org/key-share/v1\0`): the seed sealed
  (HPKE, X-Wing) to a new admin's account HPKE key (the X-Wing key their
  key binding and manifest publish), AAD binding organization id, key id,
  recipient account ref and incarnation, and the granting admin; signed by
  the granting admin's authority. Proton's `OrganizationKeyInvitation`.
- **`OrganizationAccessRequestV1`** (`kutup/org/access-request/v1\0`):
  organization id, key id, member account ref and incarnation, requesting
  admin, issued at; signed by the requesting admin's authority. Proton's
  signed `InvitationData`.
- **`OrganizationEscrowV1`** (`kutup/org/member-escrow/v1\0`): the member's
  master key sealed (HPKE, X-Wing) to the organization key, AAD binding
  organization id, key id, member account ref, incarnation and master-key
  generation. No separate signature is needed: an admin who opens it derives
  the authority from the master key and checks it equals the member's
  published authority for that incarnation, so a server can't plant an
  escrow.
- Nothing binds a username, address or organization name. Vectors and WASM
  bindings as for every format; labels go into W6's `labels.rs`.

#### Consent: private → managed (Proton's unprivatization)

1. An admin requests it (`POST /api/orgs/{id}/members/{account}/access-request`
   with a signed `OrganizationAccessRequestV1`).
2. The member sees a banner in Account, as Proton's: "An administrator of
   {org} wants to enable admin access for your account." The modal says,
   beyond Proton's text, what admin access means in Kutup: "Administrators
   will be able to reset your password and open everything in your account:
   files, photos, mail, calendars, contacts, passwords and chat backups.
   They will be able to sign in as you." Accept and Decline.
3. Before accepting, the client checks: the request is signed by a current
   admin's authority; the key certificate is signed by an admin; both
   admins' authorities against its pins, showing the usual shield (a red
   shield blocks accepting).
4. On accept it seals `OrganizationEscrowV1` and uploads it; the server
   marks the member managed. A security event (`orgAccessGranted`) records it.
- Declining deletes the request; the admin is told.

#### Revoking: managed → private (Proton's privatize)

- **Who:** an admin, as Proton (`PUT members/{id}/privatize`). See open
  question 1 for the member doing it.
- **What the server does at once:** deletes the escrow, marks the member
  private, refuses the organization's reset and sign-in for them, ends any
  admin session in the account, and records `orgAccessRevoked`.
- **What it can't undo:** an admin who ever opened the escrow may have kept
  the master key and anything it opened. Only a **master-key rotation**
  closes that for new data: the member's client makes generation g+1
  (W6's `MasterKeyGeneration`), re-wraps password and recovery, and seals
  the old master key in a keyring under the new one. Data already written
  stays readable to whoever kept the old key. Because the authority is
  derived from the master key, a rotation is a new authority and
  incarnation: correspondents see a safety-number change. Rotation itself
  is not built ([`account-identity-key.md`](account-identity-key.md),
  "Device removal"); open question 2.

#### Admin password reset and sign-in-as (owners only, managed members only)

- **Reset with data kept** (Proton's change password): the owner's client
  opens the escrow, registers a temporary password for the member (OPAQUE,
  a new key binding, an `orgReset` grant from the owner's reauth), and seals
  the master key under its export key (purpose 1). As Proton, the member's
  two-factor is turned off. Every session of the member ends; the member
  sets their own password at next sign-in.
- **Sign in as:** `POST /api/orgs/{id}/members/{account}/session` after the
  owner's reauth gives the owner's client a session for the member, marked
  as an administrator's; the client opens the escrow for the master key.
  The member's session list shows "Signed in by an administrator ({name})",
  and a security event (`orgSignIn`) is always recorded: Kutup's addition,
  since its sessions are already listed per account. The server refuses
  Chat device registration and identity changes in such a session (a server
  rule, not a crypto one: the master key could sign them).

#### New admins, admin removal, rotation, loss

- **A new admin** (promoted or created as admin) gets an
  `OrganizationKeyShareV1` from an admin who holds the key, sent with the
  role change. Their client checks the granting admin's signature against
  its pins, opens it, re-seals it as purpose 7, and activates
  (`org_key_state` pending → active). A private member becomes admin only
  after their first sign-in, as Proton.
- **Removing an admin** deletes their share and envelope. Kutup offers
  rotation at once (Proton leaves it to "Change organization keys"): a
  remaining admin's client makes a new key and certificate, re-seals every
  escrow to it (opening each with the old key), and shares it with the
  other admins. The removed admin may still know members' master keys; the
  screen says so and points those members to rotation.
- **Lost key** (no admin holds it): Proton's three steps: privatize every
  managed member, make a new key, and send each a fresh access request
  ("Your account was temporarily made private while your organization key
  was reset…").

### 4. Joining

#### Inviting an existing account (Proton's `members/invitations`)

- An owner or admin invites a username on this server
  (`POST /api/orgs/{id}/invitations {username}`); the server stores it
  against the account id, so a rename in between changes nothing.
- The invitee sees a banner in Account and accepts or declines
  (`POST /api/orgs/invitations/{id}/accept|decline`). The screen names the
  organization and the inviting admin and says: "You join as a private
  member. Administrators can't access your data or reset your password."
- **Refused at accept,** as Proton's `AcceptInvitationValidation`: the
  account already belongs to an organization with other members, or its
  organization of one holds domains ("Remove your domains, or invite the
  other person into your organization instead"). An organization of one
  without domains is dissolved on accept.
- The member joins **private**. Admins may then ask for access (§3,
  consent). Invitations expire (a setting) and can be blocked per
  organization by the invitee.
- Only accounts on this server: organizations don't federate (§6).

#### Accounts the organization creates (Proton's MANAGED)

- An owner or admin fills in username, display name, a temporary password,
  the first address on an organization domain, and "Private" (off by
  default, as `SubUserCreateModal.tsx:162`; Proton's private-user text is
  shown beside it).
- **Managed (default):** the admin's client does what Proton's
  `setupMemberKeys` does:
  - makes the member's master key (generation 1), registers the temporary
    password (OPAQUE, a fresh key binding, with an `orgCreate` grant from
    the admin's reauth) and seals the master key under its export key;
  - derives the authority and Drive keys, makes the address key, seals it
    and signs the first key list, so mail works before the member signs in;
  - seals `OrganizationEscrowV1` to the organization key.
- **Private:** the admin's client registers only the temporary password; no
  keys. The member makes everything at first sign-in, as admin-created
  accounts do today.
- **First sign-in (both):** the member must set their own password, is
  shown a new 24-word recovery phrase to save (no recovery wrap exists
  before this: the admin never sees one), and makes their Chat identity
  with their first device, as any account. A managed member is told, once
  and then in Account → Organization: "Your organization's administrators
  can reset your password and open everything in your account."
- `created_by_org` lets the organization disable, enable and delete the
  account (Proton's MANAGED-only actions). Such a member can't leave on
  their own (Kutup's rule; Proton's client offers leaving only to invited
  family members, `LeaveFamilyModal.tsx`).
- The server's sign-up gates (registration codes, the sign-up mode) don't
  apply; a setting caps created accounts per organization (§7).

### 5. Leaving, removal and address reuse

- **An invited member leaves, or is removed** ("Remove"):
  - the escrow, if any, is deleted as in privatizing (§3);
  - their addresses on the organization's domains go `freed`: the key list
    drops them, lookup and Autocrypt stop serving them, forwardings from
    them and a catch-all pointing at them end;
  - **their mail stays in their own mailbox** and still opens; their
    username address and everything else are untouched.
- **A created member is deleted** ("Delete", typing the username, Proton's
  text): the account is deleted as any account is.
- **Address reuse, as Proton:** an address on an organization domain that
  was deleted or freed can be made again by the organization at once, for
  any member (Proton's custom-domain addresses are never "permanent",
  `DeleteAddressPrompt.tsx`, `addresses/helper.ts:146`). Correspondents'
  clients pin the account id, so the new holder shows as a different
  person, never inherited trust (custom domains §8; Proton's
  `verificationPreferences.ts:43` makes the same allowance). On the
  server's own domain, the username rules and holds stay
  ([`username-renames.md`](username-renames.md)).
- **Disabling** a member: their organization addresses refuse mail at RCPT
  and can't send; nothing is freed.
- **The last owner** can't leave; they delete the organization or make
  another owner. Deleting the organization needs no other members (Kutup's
  rule); its domains are removed as custom domains §8 says, and its keys,
  shares and escrows are deleted.
- Each of these is a security event for the member (`orgJoined`, `orgLeft`,
  `orgRemoved`, `orgAccessGranted`, `orgAccessRevoked`, `orgReset`,
  `orgSignIn`); the CHECK list on `account_security_events.kind` grows in
  the same migration.

### 6. The other apps and federation

- **Federation:** an organization is local to one server. Addresses on its
  domains are ordinary Kutup addresses to other servers (key lookup, signed
  key lists, pins on the member's `AccountRef`). Nothing in the federation
  protocol changes.
- **Chat:** no organization badge or name outside the organization. Signal
  has none, and a server-asserted organization name is a phishing label.
- **Drive:** organization shared drives are out of scope; Proton's
  organization key holds members' keys, not a shared drive.
- **Calendar, Contacts:** no organization directory or free/busy in v1.
- **Pass:** no organization vaults in v1 (a later note with sharing).
- **Storage:** one pool per account, as now; server admins set it per
  account.

### 7. Limits: settings, not plans

Each limit is a registry setting ([`settings-registry.md`](settings-registry.md)),
site-wide with a value per organization: the registry gains an organization
scope (`organization_setting_overrides`, `load_for_org`), edited on the
organization's admin page. The per-account `mail_domain_overrides` goes.

| Setting | Default |
| --- | --- |
| Organizations: `everyone` / `admins approve` / `off` | as custom domains' (`everyone` on kutup.dev) |
| Managed members allowed on this server | yes |
| Members per organization | 10 |
| Accounts an organization may create | 10 |
| Domains per organization (was per account) | 3 |
| Addresses on the organization's domains | 10 per organization |
| Pending invitations per organization | 20 |
| Invitations and access requests per organization per day | 20 |
| Invitation lifetime | 14 days |
| Catch-all, its cap | as custom domains' |

Rate limits (registry): invitations, access requests, address creation,
admin resets and sign-ins-as, per account and per organization.

## Wipe sensitivity

**Before the wipe:**
1. **Schema** (in the migration squash): `organizations`,
   `organization_members` with `private`, the key, share, escrow and request
   tables, and `mail_domains.organization_id` in place of `user_id`.
   Afterwards these would be data migrations, not a wipe, but they're free
   now.
2. **W6's `MasterKeyGeneration` in every envelope** (W6 brings it): escrows
   and revocation depend on it.
3. **The new numbers and labels,** so they never collide with W1 or W5:
   account-envelope purpose 7 `OrganizationPrivateKey` (or its
   `AccountRecordV1` type), and the labels `kutup/org/key-id/v1\0`,
   `key-certificate`, `key-share`, `access-request`, `member-escrow` in
   `labels.rs`.
4. **Best before the wipe, not forced by it:** the formats themselves
   (`OrganizationKeyCertificateV1`, `OrganizationKeyShareV1`,
   `OrganizationAccessRequestV1`, `OrganizationEscrowV1`) with vectors. They
   are new formats, so adding them later needs no wipe, but after v1 any fix
   to them needs a new version.

**Nothing existing changes:** address keys, key lists, manifests and DKIM
targets bind nothing about the organization.

**Later, without a wipe:** master-key rotation, delegated roles, several
organizations per account, mail groups on organization domains,
organization vaults, drives or directory, Proton's emailed-invitation
creation mode.

## Abuse and security

- **Private members:** admins can't read, reset or sign in. A live test
  asserts no escrow exists for them and the reset and sign-in routes refuse.
- **Managed members trade privacy for recoverability.** Admins can read
  everything and act as the member. That is stated before creation, at
  consent, at first sign-in and in Account → Organization. Every reset and
  sign-in-as is a security event the member sees.
- **Invited accounts stay private unless they consent;** the server can't
  make one managed: the escrow needs the member's master key, and admins
  check it against the member's published authority.
- **Revocation is honest:** privatizing stops future access at the server,
  but only a master-key rotation protects new data from an admin who kept
  the key, and nothing protects data already exposed.
- **Admins control routing,** as any domain owner (Proton the same): they
  can free and reassign organization addresses or move MX; correspondents
  see a new person.
- **Domain transfer rules hold** (custom domains §2, §8), with the
  organization as holder; the notice goes to its owners.
- **No unwanted membership:** invitations need the invitee's accept and can
  be blocked; organization names aren't shown outside.
- **Server administrators** see organizations, members and domains, can
  disable an organization, and set its limits. They gain no access to
  escrows.

## Phasing

Each slice is its own PR with its live and browser tests; web UI per slice
by the third session.

| Slice | What | Tests |
| --- | --- | --- |
| **O1 server** (before the wipe) | tables; organization of one on the first domain; domains keyed by organization; registry organization scope | live: an account adds a domain and owns its organization of one; limits read from the organization |
| **O2 crypto** (before the wipe) | the five formats, purpose 7, labels, vectors, WASM | unit and vectors: tampered AAD, wrong recipient, an escrow whose master key derives another authority, a share signed by a non-admin |
| **O3 server** | invitations, roles, private members, admin-made addresses without keys, leaving and removal with addresses freed and reusable, catch-all on any member's address, security events | live (mail gate with CoreDNS): account 1 verifies `mail.t.co`, invites account 2, makes `b@mail.t.co`; account 2's client makes its key; both send and receive with `d=mail.t.co`; account 2 leaves; `b@` is refused, then made again for account 3, whose key list is a new account's |
| **O4 server + web** | the organization key: setup, certificate, admin shares and activation, access requests and consent, escrow, privatize, rotation on admin removal, lost-key reset | live and browser: consent and decline; an escrow opened by an admin; privatize deletes it and refuses reset; a removed admin's share gone and escrows re-sealed |
| **O5 server + web** | created accounts (managed and private), first sign-in, owner reset with data kept, sign in as, disable and delete | browser: create managed, first sign-in, reset, data still opens; sign-in-as shown in the member's sessions; a private created member refuses both |
| **O6 web** | Account → Organization (Proton's "Users and addresses"), the admin console's organizations | the account suite |
| **O7 CLI** | `kutup org` (show, invite, accept, addresses, access, leave) | CLI live tests |
| **O8** | mail groups on organization domains, storage owner `organization` | the mail groups suite |

## Open questions

1. **May a managed member make themselves private again?** Proton lets only
   admins do it. *Recommendation:* let a member who joined by invitation and
   consented withdraw their consent themselves (they gave it, they can take
   it back); members the organization created can't, as in Proton.
2. **Privatizing without master-key rotation:** rotation isn't built, and
   when it is, contacts will see a safety-number change. *Recommendation:*
   ship privatizing in O4 with the server-side cut and the honest warning,
   and plan master-key rotation as its own note before v1.
3. **Should a member be told each time an owner signs in as them?** Proton's
   client shows nothing to the member. *Recommendation:* yes, always: a
   security event and a line in their sessions, as proposed in §3.
