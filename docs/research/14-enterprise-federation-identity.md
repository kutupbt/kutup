# Enterprise federation identity: threshold roots and independent authorities

**Status:** deferred research; not the current implementation plan

**Current product direction:** Kutup first ships persistent single-key federation
pinning, authenticated old-to-new rotation, unexpected-change quarantine, and
manual fingerprint verification in one federation stack shared by Chat and
Drive. The clean replacement and implementation sequence is specified in
[`../superpowers/plans/2026-07-20-unified-federation-stack-plan.md`](../superpowers/plans/2026-07-20-unified-federation-stack-plan.md).
The system in this note is an optional future high-assurance profile for
organizations willing to operate more trust infrastructure.

## 1. Why this exists

TLS and a domain's currently published federation key establish who controls an
endpoint now. They do not, by themselves, prove that the endpoint has the same
cryptographic identity that other Kutup servers trusted previously. Persistent
pinning closes that continuity gap after first contact, but it retains three
limitations:

1. first contact is TOFU and can be substituted;
2. compromise of the one pinned private key permits an authenticated rotation;
3. two victims can be shown different internally valid views without an
   independent observer comparing them.

The enterprise profile addresses those risks with two deliberately separate
layers:

- a domain-controlled threshold root protects authorization and recovery;
- independently administered authority domains corroborate the exact public
  identity observed for that domain.

The design follows the useful part of TUF root rotation: a new root version is
accepted only when it satisfies both the old and new root thresholds. It also
borrows Matrix's ability to consult several independently selected notaries,
but does not let a notary replace the subject's own root. Transparency witnesses
provide the operational model for persistent, non-equivocating observations.

## 2. Trust hierarchy

```text
subject domain
  configurable M-of-N offline root set (recommended 3-of-5)
    -> federation-request role keys
    -> transparency-operator role keys
    -> identity-authority role keys (when this domain is an authority)
    -> transparency-witness role keys (when this domain is a witness)

independent authority domains
  each has its own manually pinned threshold root
    -> identity-authority role key
      -> short-lived attestation for the subject's exact identity epoch/hash
```

Root keys and operational keys are never interchangeable. Root keys are kept
offline and authorize infrequent policy changes. Operational keys are online,
role-scoped, independently revocable, and may overlap during rotation.

An external authority is a witness, not a recovery root. Even a full authority
quorum cannot replace a subject identity that fails the subject's own old-root
threshold. If the subject loses its root quorum, each peer administrator must
perform a conspicuous out-of-band re-pin.

## 3. Domain root documents

The signed payload is conceptually:

```text
FederationIdentityDocumentV1 {
  identityVersion: 1,
  server,
  epoch,
  previousIdentityHash?,
  issuedAt,
  rootPolicy: { threshold, keys[] },
  roles: {
    federationRequest: keys[],
    transparencyOperator: keys[],
    identityAuthority: keys[],
    transparencyWitness: keys[]
  }
}
```

Detached root signatures and authority attestations surround the payload. The
identity hash excludes all signatures. Signatures use versioned,
domain-separated, deterministic binary encoding rather than relying on a JSON
serializer's output. V1 uses Ed25519 but includes explicit algorithm identifiers
so a future hybrid/PQ profile does not need to reinterpret v1 bytes.

Epoch 1 is signed by the threshold declared in epoch 1. Epoch N+1 must:

- increment the epoch exactly once;
- hash-link to epoch N;
- satisfy epoch N's root threshold;
- satisfy epoch N+1's root threshold; and
- prove possession of every distinct key counted toward either threshold.

Clients fetch and verify every intermediate epoch. They reject rollback,
same-epoch equivocation, skipped epochs, duplicate signers, role-key reuse, and
threshold weakening below local policy.

Root-set shape is protocol-configurable. Offline tooling should recommend
3-of-5, while a peer policy may demand a different minimum key count and
threshold. Separate Ed25519 signatures are preferable to FROST initially:
they are easy to audit across Rust, WASM, Swift, and Kotlin and preserve which
custodians approved a transition.

## 4. Independent authority attestations

An authority signs a short-lived statement:

```text
FederationIdentityAttestationV1 {
  authorityDomain,
  authorityIdentityEpoch,
  authorityIdentityHash,
  authorityKeyId,
  subjectDomain,
  subjectIdentityEpoch,
  subjectIdentityHash,
  issuedAt,
  expiresAt
}
```

The consumer counts an attestation only when:

- the authority domain's genesis root was manually pinned out of band;
- its current root chain is valid from that pin;
- the signing key belongs to its current `identityAuthority` role;
- the authority is explicitly selected for this subject domain;
- the attestation is fresh; and
- every counted authority names the same subject epoch and hash.

There is intentionally no global Kutup authority list or default quorum. An
administrator might require `2 of {abc.org, bcde.org, third.example}` for one
partner and use a manual exact fingerprint for another. Merely owning distinct
DNS names does not prove organizational independence; deployments must choose
separate operators, credentials, infrastructure, and network perspectives.

Authorities persist their last observation before signing. They may renew the
same hash, but must never sign two hashes for the same subject epoch. Conflicts
are retained as evidence and not co-signed. A recommended attestation lifetime
is 30 days, with renewal beginning when 14 days remain.

Expired authority attestations do not stop federation for an already pinned,
unchanged subject epoch. They mark trust degraded and block first trust or a
new epoch until the required quorum becomes fresh again. This prevents an
authority outage from becoming a federation-wide availability outage.

## 5. First contact and rotation policy

Admission and cryptographic trust remain independent. `allowlist`, `blocklist`,
`open`, and directional rules answer whether traffic is operationally allowed.
The peer identity policy answers which cryptographic identity may use that
permission.

Each peer policy contains:

```text
PeerIdentityPolicy {
  minimumRootKeyCount,
  minimumRootThreshold,
  bootstrapMode: manualPin | authorityQuorum,
  authorityDomains[],
  authorityThreshold,
  transparencyWitnessDomains[],
  transparencyWitnessThreshold
}
```

Authority bootstrap requires a fresh configured quorum. Manual bootstrap
requires the complete expected root fingerprint obtained out of band; clicking
"trust" on a value fetched through the potentially attacked connection is not
verification.

All later epochs must pass the subject's old/new root thresholds. If the peer
policy has a non-zero authority threshold, the new epoch additionally needs a
fresh attestation quorum. Authorities are therefore an additional acceptance
condition, never an alternative signature path.

## 6. Authority operation

Any Kutup server could opt into the authority role when its own root document
authorizes an online authority key. A public issuance endpoint would accept an
exact candidate identity envelope from an allowlisted subject. Before signing,
the authority would:

1. verify a request signature from a federation key authorized by the
   candidate document;
2. independently fetch the canonical subject discovery endpoint using normal
   TLS, SSRF, address, redirect, and size protections;
3. require the live identity hash to equal the submitted candidate;
4. validate genesis or the complete transition from its persisted subject pin;
5. atomically reject or record same-epoch conflicts; and
6. return a short-lived role-key signature.

Subjects can collect and publish attestations from many authorities. Consumers
count only their locally configured subset. Normal verification is therefore
offline with respect to authorities and does not add several synchronous
network dependencies to every federated request.

## 7. Transparency integration

The root document binds the subject's transparency operator key. A remote
device-manifest checkpoint is accepted only when its operator key belongs to
the current `transparencyOperator` role.

Independent transparency witnesses are also domains with manually pinned root
identities. Their checkpoint signatures count only when the key belongs to the
current `transparencyWitness` role. One domain may provide both identity and
transparency observations, but the roles use separate keys and signatures.

This authenticates operator and witness rotation without treating keys carried
inside an untrusted proof as new trust anchors. Cross-witness checkpoint gossip
remains a separate mechanism for comparing transparency-log views.

## 8. Storage, monitoring, and failure states

Implementations would retain every local and remote root epoch, authority root
epoch, attestation, accepted policy, and conflict. First pins and epoch advances
must atomically store the complete evidence used for acceptance.

Peer states are `pending`, `trusted`, `degraded`, and `quarantined`.
Background monitoring refreshes active domains with jitter and bounded
backoff. Availability failures degrade status; cryptographic failures
quarantine both directions and suspend, rather than delete, durable ciphertext
queues.

The system must expose fingerprints, root strength, authority quorum, freshness,
history, and quarantine evidence in the admin UI. Policy weakening and
break-glass re-pinning require explicit confirmation and durable audit events.

## 9. Offline custody

The recommended five root private keys live under separate custody on offline
media or devices. Keeping all five files in the server container provides no
meaningful threshold security. An offline tool would create passphrase-encrypted
signer files, produce detached signatures, assemble old/new quorums, and export
only public identity packages to the running server. HSM support can be added
behind the same detached-signature interface.

## 10. Security boundary and adoption trigger

This profile prevents fewer than the configured root threshold from replacing
a domain identity and prevents fewer than the configured authority threshold
from satisfying authority-based first trust. It does not prevent denial of
service, prove that a valid root-quorum action was benign, or rescue a domain
that permanently loses its root quorum. A compromised same-origin web server
can also replace both application code and server-supplied trust policy; native
or reproducibly distributed clients can carry genuinely independent anchors.

Kutup should revisit this profile only when deployments need one or more of:

- protection against compromise of a single federation identity key;
- automatic high-assurance first contact without bilateral fingerprint work;
- independently attributable split-view evidence;
- regulated separation of signing duties; or
- an enterprise trust federation with operators capable of maintaining
  multiple offline custodians and authority services.

Until then, persistent TOFU pinning, visible fingerprints, authenticated
single-key rotation, quarantine, and explicit manual recovery provide a much
better security-to-complexity ratio.
