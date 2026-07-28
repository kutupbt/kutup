import type {
  AccountAddress,
  AnonymousMlsDeviceEnvelope,
  AppliedInboundMlsCommit,
  AppliedInboundMlsApplication,
  ChatTransportPort,
  DerivedMlsDeliveryCapability,
  FinalizedMlsAuthorityChange,
  FinalizedMlsClose,
  FinalizedMlsMembershipChange,
  FinalizedMlsOwnerChange,
  FinalizedMlsPolicyChange,
  FinalizedMlsRecovery,
  JoinedMlsConversation,
  LocalMlsConversationRecord,
  LocalMlsGroupState,
  MlsConversationMember,
  MlsGroupAuthorizationPolicy,
  MlsGroupCryptographicPolicy,
  MlsIncarnationRecovery,
  MlsInvitationFeedback,
  MlsMailboxEnvelope,
  MlsOwnerCandidate,
  MlsOutboxEntry,
  MlsWelcomeInspection,
  PendingMlsAuthorityChange,
  PendingMlsClose,
  PendingMlsMembershipChange,
  PendingMlsOwnerApprovalRequest,
  PendingMlsOwnerChange,
  PendingMlsPolicyChange,
  PendingMlsRecovery,
  PendingMlsInvitation,
  PreparedMlsGroupGenesis,
  VerifiedMlsCredential,
  VerifiedMlsKeyPackage,
  WasmChatClientHandle,
} from './types'
import {
  canonicalAccountAddress,
  parseAccountAddress,
} from './identity'

const MLS_PROTOCOL_VERSION = 1
const DEFAULT_KEY_PACKAGE_TARGET = 20
const KEY_PACKAGE_LIFETIME_SECONDS = 30 * 24 * 60 * 60
const MAX_MAILBOX_PAGES = 64
const MAX_CONTROL_HISTORY_PAGES = 1024

type CryptoLock = <T>(operation: () => Promise<T>) => Promise<T>

export type MlsSendFailureStage =
  | 'conversation'
  | 'encryption'
  | 'recipient'
  | 'capability'
  | 'capability_binding'
  | 'key_packages'
  | 'envelope_staging'
  | 'outbox_attempt'
  | 'submission'
  | 'receipt'

/** A stable, identifier-free failure stage suitable for user and test diagnostics. */
export class MlsSendError extends Error {
  constructor(readonly stage: MlsSendFailureStage, cause: unknown) {
    super(`MLS group send failed during ${stage.replace('_', ' ')}.`, { cause })
    this.name = 'MlsSendError'
  }
}

export interface VerifiedMlsInvitation {
  conversationId: string
  incarnation: number
  mlsGroupId: string
  invitedEpoch: number
  /**
   * Exact device roster produced by the shared transparency verifier from the
   * authenticated participant-bootstrap/control history. A server status label
   * is never sufficient.
   */
  expectedMembers: VerifiedMlsCredential[]
}

export interface AcceptedMlsInvitation {
  group: LocalMlsGroupState
  serverAccepted: boolean
  resumed: boolean
}

interface MlsKeyPackageCount {
  deviceId: number
  available: number
}

/**
 * Unadvertised browser coordinator for the MLS-specific lifecycle.
 *
 * It deliberately stays separate from ChatService until the authenticated
 * participant-history verifier and group UI are complete. All OpenMLS state
 * transitions run under the same cross-tab crypto lock as the 1:1 engine.
 */
export class MlsConversationService {
  private readonly publishedCapabilityEpochs = new Map<string, string>()

  constructor(
    private readonly client: WasmChatClientHandle,
    private readonly transport: ChatTransportPort,
    private readonly withCryptoLock: CryptoLock,
    private readonly deviceId: number,
    private readonly selfAddress?: AccountAddress,
  ) {}

  /**
   * Prepare group crypto and exact retry material before the first network
   * write. Each authority policy is authenticated by the shared Rust engine;
   * JavaScript only coordinates the resulting typed policies.
   */
  async createGroup(
    creator: AccountAddress,
    authorityDomains: string[],
  ): Promise<PreparedMlsGroupGenesis> {
    const domains = requireAuthorityDomains(authorityDomains)
    const policies: unknown[] = []
    for (const domain of domains) {
      policies.push(
        await this.withCryptoLock(() =>
          this.client.fetchVerifiedMlsOrderingPolicy(domain),
        ),
      )
    }
    const browserCrypto = requireBrowserCrypto()
    const conversationId = browserCrypto.randomUUID()
    const groupId = browserCrypto.getRandomValues(new Uint8Array(32))
    const prepared = await this.withCryptoLock(() =>
      this.client.prepareMlsGroupGenesis(
        conversationId,
        groupId,
        creator,
        policies,
        String(Math.floor(Date.now() / 1000)),
      ),
    )
    validatePreparedGenesis(prepared, conversationId, groupId)
    const published = await this.publishPreparedGenesis(prepared.conversation)
    await this.publishCurrentDeliveryCapability(published)
    return { group: prepared.group, conversation: published }
  }

  async conversations(): Promise<LocalMlsConversationRecord[]> {
    return this.withCryptoLock(() => this.client.localMlsConversations())
  }

  async addMember(
    conversationId: string,
    recipient: AccountAddress,
  ): Promise<FinalizedMlsMembershipChange> {
    const conversation = await this.requireActiveConversation(conversationId)
      .catch(cause => { throw new MlsSendError('conversation', cause) })
    requireCanonicalAddress(recipient)
    const canonical = canonicalAccountAddress(recipient)
    if (conversation.currentRoster.some(
      member => canonicalAccountAddress(member.address) === canonical,
    )) {
      throw new Error('account is already an MLS group member')
    }
    const additions = await this.withCryptoLock(() =>
      this.client.fetchVerifiedIdentifiedMlsKeyPackages(
        recipient,
        conversationId,
        String(conversation.request.genesis.incarnation),
        String(Math.floor(Date.now() / 1000)),
      ),
    )
    if (!Array.isArray(additions) || additions.length < 1 || additions.length > 32) {
      throw new Error('identified MLS KeyPackage claim returned no destination devices')
    }
    const nextRoster = [...conversation.currentRoster, {
      address: recipient,
      isAdmin: false,
    }].sort(compareMembers)
    return this.changeGroupMembership(conversationId, nextRoster, additions)
  }

  async removeMember(
    conversationId: string,
    member: AccountAddress,
  ): Promise<FinalizedMlsMembershipChange> {
    const conversation = await this.requireActiveConversation(conversationId)
    const canonical = canonicalAccountAddress(requireCanonicalAddress(member))
    const nextRoster = conversation.currentRoster.filter(
      current => canonicalAccountAddress(current.address) !== canonical,
    )
    if (nextRoster.length === conversation.currentRoster.length) {
      throw new Error('account is not an MLS group member')
    }
    return this.changeGroupMembership(conversationId, nextRoster, [])
  }

  async setAdministrator(
    conversationId: string,
    member: AccountAddress,
    isAdmin: boolean,
  ): Promise<FinalizedMlsMembershipChange> {
    const conversation = await this.requireActiveConversation(conversationId)
    const canonical = canonicalAccountAddress(requireCanonicalAddress(member))
    let changed = false
    const nextRoster = conversation.currentRoster.map((current) => {
      if (canonicalAccountAddress(current.address) !== canonical) return current
      changed = current.isAdmin !== isAdmin
      return { ...current, isAdmin }
    })
    if (!changed) throw new Error('MLS administrator role is already in the requested state')
    return this.changeGroupMembership(conversationId, nextRoster, [])
  }

  /**
   * Replay every exact pending genesis after restart. No crypto material or
   * request field is regenerated.
   */
  async reconcilePendingGroupGeneses(): Promise<LocalMlsConversationRecord[]> {
    const records = await this.withCryptoLock(() =>
      this.client.localMlsConversations(),
    )
    const published: LocalMlsConversationRecord[] = []
    for (const record of records) {
      if (record.status === 'pending_genesis') {
        published.push(await this.publishPreparedGenesis(record))
      }
    }
    return published
  }

  /**
   * Atomically stage one add-only, remove-only, or administrator-only MLS
   * roster transition, then replay its exact destination deliveries and
   * quorum request. All signature and quorum decisions remain inside the
   * shared Rust engine.
   */
  async changeGroupMembership(
    conversationId: string,
    nextRoster: MlsConversationMember[],
    additions: unknown[],
  ): Promise<FinalizedMlsMembershipChange> {
    const browserCrypto = requireBrowserCrypto()
    const records = await this.withCryptoLock(() =>
      this.client.localMlsConversations(),
    )
    const conversation = records.find(
      (record) =>
        record.request.genesis.conversationId === conversationId
        && record.status === 'active',
    )
    if (!conversation) {
      throw new Error('active local MLS conversation is unavailable')
    }
    const groupId = decodeCanonicalBase64(
      conversation.request.genesis.mlsGroupId,
      16,
      255,
    )
    const prepared = await this.withCryptoLock(() =>
      this.client.prepareMlsMembershipChange(
        groupId,
        browserCrypto.randomUUID(),
        nextRoster,
        additions,
        String(Math.floor(Date.now() / 1000)),
      ),
    )
    validatePendingMembershipChange(prepared.control, groupId)
    const finalized = await this.publishPendingMembershipChange(prepared.control)
    await this.publishCurrentDeliveryCapability(finalized.conversation)
    return finalized
  }

  /** Replay exact staged deliveries and the exact signed block after restart. */
  async reconcilePendingMembershipChanges(): Promise<FinalizedMlsMembershipChange[]> {
    const pending = await this.withCryptoLock(() =>
      this.client.pendingMlsMembershipChanges(),
    )
    const finalized: FinalizedMlsMembershipChange[] = []
    for (const control of pending) {
      validatePendingMembershipChange(control, Uint8Array.from(control.mlsGroupId))
      const result = await this.publishPendingMembershipChange(control)
      await this.publishCurrentDeliveryCapability(result.conversation)
      finalized.push(result)
    }
    return finalized
  }

  /**
   * Replace the ordering-authority set through owner authorization and joint
   * old/new quorums. Each supplied server policy is authenticated first.
   */
  async setAuthorities(
    conversationId: string,
    authorityDomains: string[],
  ): Promise<FinalizedMlsAuthorityChange> {
    const conversation = await this.requireActiveConversation(conversationId)
    const domains = requireAuthorityDomains(authorityDomains)
    const currentDomains = conversation.currentAuthoritySet.authorities
      .map(authority => authority.domain)
      .sort()
    if (domains.length === currentDomains.length
      && domains.every((domain, index) => domain === currentDomains[index])) {
      throw new Error('MLS authority set is already in the requested state')
    }
    const policies: unknown[] = []
    for (const domain of domains) {
      policies.push(await this.withCryptoLock(() =>
        this.client.fetchVerifiedMlsOrderingPolicy(domain)))
    }
    const groupId = decodeCanonicalBase64(
      conversation.request.genesis.mlsGroupId,
      16,
      255,
    )
    const prepared = await this.withCryptoLock(() =>
      this.client.prepareMlsAuthorityChange(
        groupId,
        requireBrowserCrypto().randomUUID(),
        policies,
        String(Math.floor(Date.now() / 1000)),
      ))
    validatePendingAuthorityChange(prepared.control, groupId)
    const finalized = await this.publishPendingAuthorityChange(prepared.control)
    await this.publishCurrentDeliveryCapability(finalized.conversation)
    return finalized
  }

  async reconcilePendingAuthorityChanges(): Promise<FinalizedMlsAuthorityChange[]> {
    const pending = await this.withCryptoLock(() =>
      this.client.pendingMlsAuthorityChanges())
    const finalized: FinalizedMlsAuthorityChange[] = []
    for (const control of pending) {
      validatePendingAuthorityChange(control, Uint8Array.from(control.mlsGroupId))
      const result = await this.publishPendingAuthorityChange(control)
      await this.publishCurrentDeliveryCapability(result.conversation)
      finalized.push(result)
    }
    return finalized
  }

  /**
   * Replace the pseudonymous owner set and its encrypted account bindings.
   * The caller supplies only credentials independently obtained from the
   * intended group members; Rust validates the exact mapping and quorum.
   */
  async setOwners(
    conversationId: string,
    owners: Array<{ address: AccountAddress; ownerId: string; publicKey: string }>,
  ): Promise<FinalizedMlsOwnerChange | null> {
    const conversation = await this.requireActiveConversation(conversationId)
    if (owners.length < 1 || owners.length > 1024) {
      throw new Error('MLS owner set must contain 1-1024 members')
    }
    const byAddress = new Map<string, { ownerId: string; publicKey: string }>()
    for (const owner of owners) {
      const address = canonicalAccountAddress(owner.address)
      if (
        byAddress.has(address)
        || !/^[0-9a-f]{64}$/.test(owner.ownerId)
        || decodeCanonicalBase64(owner.publicKey, 32, 32).length !== 32
      ) {
        throw new Error('invalid or duplicate MLS owner credential')
      }
      byAddress.set(address, { ownerId: owner.ownerId, publicKey: owner.publicKey })
    }
    const rosterAddresses = new Set(
      conversation.currentRoster.map(member => canonicalAccountAddress(member.address)),
    )
    if ([...byAddress.keys()].some(address => !rosterAddresses.has(address))) {
      throw new Error('MLS owner candidate is not a current group member')
    }
    const nextRoster = conversation.currentRoster.map(member => ({
      ...member,
      ownerId: byAddress.get(canonicalAccountAddress(member.address))?.ownerId,
    }))
    const nextOwners = [...byAddress.values()]
      .sort((left, right) => left.ownerId.localeCompare(right.ownerId))
    const nextOwnerSet = {
      sequence: conversation.currentOwnerSet.sequence + 1,
      owners: nextOwners,
      requiredQuorum: Math.floor((2 * nextOwners.length) / 3) + 1,
    }
    const groupId = decodeCanonicalBase64(
      conversation.request.genesis.mlsGroupId,
      16,
      255,
    )
    const prepared = await this.withCryptoLock(() =>
      this.client.prepareMlsOwnerChange(
        groupId,
        requireBrowserCrypto().randomUUID(),
        nextRoster,
        nextOwnerSet,
        String(Math.floor(Date.now() / 1000)),
      ))
    validatePendingOwnerChange(prepared.control, groupId)
    if (!await this.withCryptoLock(() => this.client.mlsOwnerChangeHasQuorum(groupId))) {
      await this.publishOwnerApprovalRequest(groupId)
      return null
    }
    const finalized = await this.publishPendingOwnerChange(prepared.control)
    await this.publishCurrentDeliveryCapability(finalized.conversation)
    return finalized
  }

  async reconcilePendingOwnerChanges(): Promise<FinalizedMlsOwnerChange[]> {
    const pending = await this.withCryptoLock(() => this.client.pendingMlsOwnerChanges())
    const finalized: FinalizedMlsOwnerChange[] = []
    for (const control of pending) {
      const groupId = Uint8Array.from(control.mlsGroupId)
      validatePendingOwnerChange(control, groupId)
      if (!await this.withCryptoLock(() => this.client.mlsOwnerChangeHasQuorum(groupId))) {
        await this.publishOwnerApprovalRequest(groupId)
        continue
      }
      const result = await this.publishPendingOwnerChange(control)
      await this.publishCurrentDeliveryCapability(result.conversation)
      finalized.push(result)
    }
    return finalized
  }

  async closeConversation(conversationId: string): Promise<FinalizedMlsClose | null> {
    const conversation = await this.requireActiveConversation(conversationId)
    const groupId = decodeCanonicalBase64(
      conversation.request.genesis.mlsGroupId,
      16,
      255,
    )
    const prepared = await this.withCryptoLock(() =>
      this.client.prepareMlsClose(
        groupId,
        requireBrowserCrypto().randomUUID(),
        String(Math.floor(Date.now() / 1000)),
      ))
    validatePendingClose(prepared.control, groupId)
    if (!await this.withCryptoLock(() => this.client.mlsCloseHasOwnerQuorum(groupId))) {
      await this.publishOwnerApprovalRequest(groupId)
      return null
    }
    return this.publishPendingClose(prepared.control)
  }

  async reconcilePendingCloses(): Promise<FinalizedMlsClose[]> {
    const pending = await this.withCryptoLock(() => this.client.pendingMlsCloses())
    const finalized: FinalizedMlsClose[] = []
    for (const control of pending) {
      const groupId = Uint8Array.from(control.mlsGroupId)
      validatePendingClose(control, groupId)
      if (!await this.withCryptoLock(() => this.client.mlsCloseHasOwnerQuorum(groupId))) {
        await this.publishOwnerApprovalRequest(groupId)
        continue
      }
      finalized.push(await this.publishPendingClose(control))
    }
    return finalized
  }

  async setApplicationSenderPolicy(
    conversationId: string,
    applicationSenders: 'members' | 'administrators',
  ): Promise<FinalizedMlsPolicyChange | null> {
    const conversation = await this.requireActiveConversation(conversationId)
    const groupId = decodeCanonicalBase64(
      conversation.request.genesis.mlsGroupId,
      16,
      255,
    )
    const nextPolicy: MlsGroupAuthorizationPolicy = {
      policyVersion: 1,
      sequence: conversation.currentAuthorizationPolicy.sequence + 1,
      applicationSenders: applicationSenders === 'members' ? 1 : 2,
    }
    const prepared = await this.withCryptoLock(() =>
      this.client.prepareMlsAuthorizationPolicyChange(
        groupId,
        requireBrowserCrypto().randomUUID(),
        nextPolicy,
        String(Math.floor(Date.now() / 1000)),
      ))
    validatePendingPolicyChange(prepared.control, groupId)
    if (!await this.withCryptoLock(() => this.client.mlsPolicyChangeHasOwnerQuorum(groupId))) {
      await this.publishOwnerApprovalRequest(groupId)
      return null
    }
    return this.publishPendingPolicyChange(prepared.control)
  }

  async tightenMaximumApplicationPlaintext(
    conversationId: string,
    maximumBytes: number,
  ): Promise<FinalizedMlsPolicyChange | null> {
    const conversation = await this.requireActiveConversation(conversationId)
    if (
      !Number.isSafeInteger(maximumBytes)
      || maximumBytes < 1024
      || maximumBytes >= conversation.currentCryptographicPolicy.maximumApplicationPlaintextBytes
    ) {
      throw new Error('MLS plaintext maximum must tighten the current policy within V1 bounds')
    }
    const groupId = decodeCanonicalBase64(
      conversation.request.genesis.mlsGroupId,
      16,
      255,
    )
    const nextPolicy: MlsGroupCryptographicPolicy = {
      ...conversation.currentCryptographicPolicy,
      sequence: conversation.currentCryptographicPolicy.sequence + 1,
      maximumApplicationPlaintextBytes: maximumBytes,
    }
    const prepared = await this.withCryptoLock(() =>
      this.client.prepareMlsCryptographicPolicyChange(
        groupId,
        requireBrowserCrypto().randomUUID(),
        nextPolicy,
        String(Math.floor(Date.now() / 1000)),
      ))
    validatePendingPolicyChange(prepared.control, groupId)
    if (!await this.withCryptoLock(() => this.client.mlsPolicyChangeHasOwnerQuorum(groupId))) {
      await this.publishOwnerApprovalRequest(groupId)
      return null
    }
    return this.publishPendingPolicyChange(prepared.control)
  }

  async reconcilePendingPolicyChanges(): Promise<FinalizedMlsPolicyChange[]> {
    const pending = await this.withCryptoLock(() => this.client.pendingMlsPolicyChanges())
    const finalized: FinalizedMlsPolicyChange[] = []
    for (const control of pending) {
      const groupId = Uint8Array.from(control.mlsGroupId)
      validatePendingPolicyChange(control, groupId)
      if (!await this.withCryptoLock(() => this.client.mlsPolicyChangeHasOwnerQuorum(groupId))) {
        await this.publishOwnerApprovalRequest(groupId)
        continue
      }
      finalized.push(await this.publishPendingPolicyChange(control))
    }
    return finalized
  }

  /**
   * Replace an unavailable group incarnation using the current owners rather
   * than the old ordering quorum. The account roster and owner set are fixed;
   * only the authenticated ordering-authority subset may be selected.
   */
  async recoverConversation(
    conversationId: string,
    authorityDomains?: string[],
  ): Promise<FinalizedMlsRecovery | null> {
    const conversation = await this.requireActiveConversation(conversationId)
    const domains = requireAuthorityDomains(
      authorityDomains
      ?? conversation.currentAuthoritySet.authorities.map(authority => authority.domain),
    )
    const policies: unknown[] = []
    for (const domain of domains) {
      policies.push(await this.withCryptoLock(() =>
        this.client.fetchVerifiedMlsOrderingPolicy(domain)))
    }
    const self = requireCanonicalAddress(this.selfAddress)
    const selfCanonical = canonicalAccountAddress(self)
    const additions: VerifiedMlsKeyPackage[] = []
    const now = String(Math.floor(Date.now() / 1000))
    for (const member of conversation.currentRoster) {
      const canonical = canonicalAccountAddress(requireCanonicalAddress(member.address))
      const packages = await this.withCryptoLock(() =>
        this.client.fetchVerifiedIdentifiedMlsKeyPackages(
          member.address,
          conversationId,
          String(conversation.request.genesis.incarnation),
          now,
        ))
      if (!Array.isArray(packages) || packages.length < 1 || packages.length > 32) {
        throw new Error('recovery KeyPackage claim returned an invalid device set')
      }
      let retained = 0
      for (const keyPackage of packages) {
        validateVerifiedKeyPackage(keyPackage, canonical)
        if (canonical === selfCanonical && keyPackage.wire.deviceId === this.deviceId) continue
        additions.push(keyPackage)
        retained += 1
      }
      if (canonical !== selfCanonical && retained === 0) {
        throw new Error('recovery omitted every device for a preserved member')
      }
    }
    const browserCrypto = requireBrowserCrypto()
    const oldGroupId = decodeCanonicalBase64(
      conversation.request.genesis.mlsGroupId,
      16,
      255,
    )
    const newGroupId = browserCrypto.getRandomValues(new Uint8Array(32))
    const prepared = await this.withCryptoLock(() =>
      this.client.prepareMlsGroupRecovery(
        oldGroupId,
        newGroupId,
        browserCrypto.randomUUID(),
        policies,
        additions,
        now,
      ))
    validatePendingRecovery(prepared.control, oldGroupId, newGroupId)
    if (!await this.withCryptoLock(() =>
      this.client.mlsRecoveryHasOwnerQuorum(oldGroupId))) {
      await this.publishOwnerApprovalRequest(oldGroupId)
      return null
    }
    const finalized = await this.publishPendingRecovery(prepared.control)
    await this.publishCurrentDeliveryCapability(finalized.conversation)
    return finalized
  }

  async reconcilePendingRecoveries(): Promise<FinalizedMlsRecovery[]> {
    const pending = await this.withCryptoLock(() => this.client.pendingMlsRecoveries())
    const finalized: FinalizedMlsRecovery[] = []
    for (const control of pending) {
      const oldGroupId = Uint8Array.from(control.mlsGroupId)
      validatePendingRecovery(
        control,
        oldGroupId,
        Uint8Array.from(control.newMlsGroupId),
      )
      if (!await this.withCryptoLock(() =>
        this.client.mlsRecoveryHasOwnerQuorum(oldGroupId))) {
        await this.publishOwnerApprovalRequest(oldGroupId)
        continue
      }
      const result = await this.publishPendingRecovery(control)
      await this.publishCurrentDeliveryCapability(result.conversation)
      finalized.push(result)
    }
    return finalized
  }

  async ownerCandidates(conversationId: string): Promise<MlsOwnerCandidate[]> {
    const conversation = await this.requireActiveConversation(conversationId)
    const groupId = decodeCanonicalBase64(
      conversation.request.genesis.mlsGroupId,
      16,
      255,
    )
    return this.withCryptoLock(() => this.client.mlsOwnerCandidates(groupId))
  }

  /**
   * Publish this member's proof-of-possession credential inside MLS. The
   * deterministic per-epoch outbox makes crashes retry-safe and keeps ordering
   * servers from learning which account is being considered for ownership.
   */
  async publishOwnerCandidate(conversationId: string): Promise<MlsOwnerCandidate> {
    const conversation = await this.requireActiveConversation(conversationId)
    return this.publishOwnerCandidateForRecord(conversation)
  }

  async setOwnerRole(
    conversationId: string,
    member: AccountAddress,
    isOwner: boolean,
  ): Promise<FinalizedMlsOwnerChange | null> {
    const conversation = await this.requireActiveConversation(conversationId)
    const canonical = canonicalAccountAddress(requireCanonicalAddress(member))
    const rosterMember = conversation.currentRoster.find(
      current => canonicalAccountAddress(current.address) === canonical,
    )
    if (!rosterMember) throw new Error('account is not an MLS group member')
    if (Boolean(rosterMember.ownerId) === isOwner) {
      throw new Error('MLS owner role is already in the requested state')
    }
    const publicOwners = new Map(
      conversation.currentOwnerSet.owners.map(owner => [owner.ownerId, owner]),
    )
    const owners = conversation.currentRoster.flatMap((current) => {
      if (!current.ownerId) return []
      const owner = publicOwners.get(current.ownerId)
      if (!owner) throw new Error('MLS private owner mapping differs from the public owner set')
      return [{ address: current.address, ...owner }]
    })
    if (isOwner) {
      const candidate = (await this.ownerCandidates(conversationId)).find(
        current => canonicalAccountAddress(current.account) === canonical,
      )
      if (!candidate) {
        throw new Error('member must publish an authenticated MLS owner candidate first')
      }
      owners.push({
        address: candidate.account,
        ownerId: candidate.ownerId,
        publicKey: candidate.publicKey,
      })
    } else {
      const index = owners.findIndex(owner => canonicalAccountAddress(owner.address) === canonical)
      if (index >= 0) owners.splice(index, 1)
    }
    return this.setOwners(conversationId, owners)
  }

  async pendingOwnerApprovalRequests(): Promise<PendingMlsOwnerApprovalRequest[]> {
    return this.withCryptoLock(() => this.client.pendingMlsOwnerApprovalRequests())
  }

  async approveOwnerGovernance(conversationId: string): Promise<void> {
    const conversation = await this.requireActiveConversation(conversationId)
    const groupId = decodeCanonicalBase64(
      conversation.request.genesis.mlsGroupId,
      16,
      255,
    )
    const entry = await this.withCryptoLock(() =>
      this.client.approveMlsOwnerApprovalRequest(
        groupId,
        String(Math.floor(Date.now() / 1000)),
      ))
    if (entry) await this.deliverApplicationEntry(entry)
  }

  async rejectOwnerGovernance(conversationId: string): Promise<void> {
    const conversation = await this.requireActiveConversation(conversationId)
    const groupId = decodeCanonicalBase64(
      conversation.request.genesis.mlsGroupId,
      16,
      255,
    )
    await this.withCryptoLock(() => this.client.rejectMlsOwnerApprovalRequest(groupId))
  }

  async maintainKeyPackages(
    manifestVersion: number,
    target = DEFAULT_KEY_PACKAGE_TARGET,
  ): Promise<number> {
    requireSafePositiveInteger(manifestVersion, 'manifest version')
    if (!Number.isInteger(target) || target < 1 || target > 100) {
      throw new Error('MLS KeyPackage target must be between 1 and 100')
    }
    const count = requireKeyPackageCount(
      await this.transport.mlsKeyPackageCount(this.deviceId),
      this.deviceId,
    )
    if (count.available >= target) return count.available

    const now = Math.floor(Date.now() / 1000)
    const packages: unknown[] = []
    for (let index = count.available; index < target; index += 1) {
      packages.push(
        await this.withCryptoLock(() =>
          this.client.generateMlsKeyPackage(
            String(manifestVersion),
            String(now),
            String(now + KEY_PACKAGE_LIFETIME_SECONDS),
          ),
        ),
      )
    }
    const response = requireKeyPackageCount(
      await this.transport.publishMlsKeyPackages({
        protocolVersion: MLS_PROTOCOL_VERSION,
        manifestVersion,
        deviceId: this.deviceId,
        keyPackages: packages,
      }),
      this.deviceId,
    )
    if (response.available < target) {
      throw new Error('MLS KeyPackage publication did not reach the requested target')
    }
    return response.available
  }

  async fetchVerifiedKeyPackages(
    recipient: AccountAddress,
    capability: Uint8Array,
  ): Promise<unknown[]> {
    if (
      !recipient.server
      || recipient.username.length < 3
      || capability.length !== 16
    ) {
      throw new Error('anonymous MLS KeyPackage retrieval requires a canonical recipient')
    }
    return this.withCryptoLock(() =>
      this.client.fetchVerifiedMlsKeyPackages(
        recipient,
        capability,
        String(Math.floor(Date.now() / 1000)),
      ),
    )
  }

  async sendText(conversationId: string, text: string): Promise<{
    delivered: boolean
    deduplicated: boolean
    attempts: number
  }> {
    if (!text.trim() || text.length > 64 * 1024) {
      throw new Error('MLS group message must contain 1-65536 characters')
    }
    const conversation = await this.requireActiveConversation(conversationId)
    let groupId: Uint8Array
    let sendId: string
    try {
      groupId = decodeCanonicalBase64(
        conversation.request.genesis.mlsGroupId,
        16,
        255,
      )
      sendId = requireBrowserCrypto().randomUUID()
    } catch (cause) {
      throw new MlsSendError('encryption', cause)
    }
    const entry = await this.withCryptoLock(() => this.client.createMlsTextMessage(
        sendId,
        conversationId,
        String(conversation.request.genesis.incarnation),
        groupId,
        new Date().toISOString(),
        text,
        String(Date.now()),
      ))
      .catch(cause => { throw new MlsSendError('encryption', cause) })
    await this.deliverApplicationEntry(entry).catch(cause => {
      if (cause instanceof MlsSendError) throw cause
      throw new MlsSendError('envelope_staging', cause)
    })
    return {
      delivered: true,
      deduplicated: entry.attempts > 0,
      attempts: Math.max(1, entry.expectedRecipients.length),
    }
  }

  async reconcilePendingApplicationMessages(): Promise<number> {
    const pending = await this.withCryptoLock(() =>
      this.client.pendingMlsApplicationMessages(),
    )
    for (const entry of pending) await this.deliverApplicationEntry(entry)
    return pending.length
  }

  async invitations(): Promise<PendingMlsInvitation[]> {
    const now = Math.floor(Date.now() / 1000)
    const invitations = await this.transport.listMlsInvitations()
    for (const invitation of invitations) validateInvitation(invitation, now)
    return invitations
  }

  async invitationFeedback(): Promise<MlsInvitationFeedback[]> {
    const feedback = await this.transport.listMlsInvitationFeedback()
    for (const entry of feedback) validateInvitationFeedback(entry)
    return feedback
  }

  rejectInvitation(invitation: PendingMlsInvitation): Promise<void> {
    validateInvitation(invitation, Math.floor(Date.now() / 1000))
    return this.transport
      .respondMlsInvitation({
        conversationId: invitation.conversationId,
        incarnation: invitation.incarnation,
        accept: false,
      })
      .then(() => undefined)
  }

  /**
   * Decrypt a pending Welcome into untrusted credential claims without joining.
   * The caller must resolve every `account#device` claim through authenticated
   * transparency history before constructing `VerifiedMlsInvitation`.
   */
  async inspectInvitation(pending: PendingMlsInvitation): Promise<MlsWelcomeInspection> {
    validateInvitation(pending, Math.floor(Date.now() / 1000))
    const envelopes = await this.membershipEnvelopes(
      pending.conversationId,
      pending.incarnation,
    )
    if (envelopes.length !== 1) {
      throw new Error('MLS invitation must have exactly one control envelope for this device')
    }
    const groupId = decodeCanonicalBase64(pending.mlsGroupId, 16, 255)
    const welcome = decodeCanonicalBase64(envelopes[0].opaqueEnvelope, 1, 1024 * 1024)
    const inspection = await this.withCryptoLock(() =>
      this.client.inspectMlsWelcome(groupId, welcome),
    )
    if (
      inspection.epoch !== pending.invitedEpoch
      || !equalBytes(inspection.mlsGroupId, groupId)
      || inspection.claimedMembers.length < 1
      || inspection.claimedMembers.length > 1000
      || inspection.privateControlState.protocolVersion !== MLS_PROTOCOL_VERSION
      || inspection.privateControlState.conversationId !== pending.conversationId
      || inspection.privateControlState.incarnation !== pending.incarnation
      || inspection.privateControlState.epoch !== inspection.epoch
    ) {
      throw new Error('MLS Welcome differs from pending invitation metadata')
    }
    return inspection
  }

  /**
   * Resolve every untrusted Welcome claim through the shared Rust engine's
   * authenticated policy, manifest-chain, transparency, and device-key checks.
   * No JavaScript or server-provided status label can mint a verified roster.
   */
  async verifyInvitation(pending: PendingMlsInvitation): Promise<VerifiedMlsInvitation> {
    const inspection = await this.inspectInvitation(pending)
    const expectedMembers = await this.withCryptoLock(() =>
      this.client.resolveMlsWelcomeClaims(inspection.claimedMembers),
    )
    if (
      expectedMembers.length !== inspection.claimedMembers.length
      || expectedMembers.some((member, index) => {
        const claim = inspection.claimedMembers[index]
        return member.credentialIdentity !== claim.credentialIdentity
          || !equalBytes(member.credentialPublicKey, Uint8Array.from(claim.credentialPublicKey))
      })
    ) {
      throw new Error('shared verifier returned a roster different from the inspected Welcome')
    }
    const verified = {
      conversationId: pending.conversationId,
      incarnation: pending.incarnation,
      mlsGroupId: pending.mlsGroupId,
      invitedEpoch: pending.invitedEpoch,
      expectedMembers,
    }
    validateVerifiedInvitation(pending, verified)
    return verified
  }

  async acceptInvitation(pending: PendingMlsInvitation): Promise<AcceptedMlsInvitation> {
    const verified = await this.verifyInvitation(pending)
    return this.acceptVerifiedInvitation(pending, verified)
  }

  /**
   * Apply active-group membership Commits strictly in mailbox order. The
   * shared engine verifies the exact quorum-certified public block and writes
   * its mailbox receipt atomically with the OpenMLS epoch; HTTP acknowledgement
   * happens only after that transaction succeeds.
   */
  async reconcileInboundMembershipCommits(): Promise<AppliedInboundMlsCommit[]> {
    const records = await this.withCryptoLock(() =>
      this.client.localMlsConversations(),
    )
    const applied: AppliedInboundMlsCommit[] = []
    for (const envelope of await this.allMembershipEnvelopes()) {
      const receipt = await this.withCryptoLock(() =>
        this.client.processedMlsControlEnvelope(envelope.id),
      )
      if (receipt) {
        if (
          receipt.envelopeId !== envelope.id
          || receipt.cursor !== envelope.cursor
          || receipt.sendId !== envelope.sendId
          || receipt.conversationId !== envelope.conversationId
          || receipt.incarnation !== envelope.incarnation
        ) {
          throw new Error('MLS mailbox replay differs from its durable receipt')
        }
        await this.transport.ackMlsMailbox(this.deviceId, [envelope.id])
        continue
      }
      const recordIndex = records.findIndex(
        (record) =>
          record.status === 'active'
          && record.request.genesis.conversationId === envelope.conversationId
          && record.request.genesis.incarnation === envelope.incarnation,
      )
      if (recordIndex < 0) continue
      const record = records[recordIndex]
      const groupId = decodeCanonicalBase64(
        record.request.genesis.mlsGroupId,
        16,
        255,
      )
      const commit = decodeCanonicalBase64(
        envelope.opaqueEnvelope,
        1,
        1024 * 1024,
      )
      const inspection = await this.withCryptoLock(() =>
        this.client.inspectInboundMlsCommit(groupId, commit),
      )
      if (
        !equalBytes(inspection.mlsGroupId, groupId)
        || inspection.epochBefore !== record.lastFinalizedEpoch
        || inspection.epochAfter !== record.lastFinalizedEpoch + 1
        || inspection.privateControlState.conversationId !== envelope.conversationId
        || inspection.privateControlState.incarnation !== envelope.incarnation
        || inspection.privateControlState.epoch !== inspection.epochAfter
      ) {
        throw new Error('inbound MLS Commit differs from the durable conversation pin')
      }
      const expectedMembers = await this.withCryptoLock(() =>
        this.client.resolveMlsWelcomeClaims(inspection.claimedMembers),
      )
      if (
        expectedMembers.length !== inspection.claimedMembers.length
        || expectedMembers.some((member, index) => {
          const claim = inspection.claimedMembers[index]
          return member.credentialIdentity !== claim.credentialIdentity
            || !equalBytes(
              member.credentialPublicKey,
              Uint8Array.from(claim.credentialPublicKey),
            )
        })
      ) {
        throw new Error('shared verifier returned a roster different from the MLS Commit')
      }
      const history = await this.transport.fetchMlsControlHistory(
        envelope.conversationId!,
        envelope.incarnation!,
        String(record.lastFinalizedHeight),
        1,
      )
      if (history.entryCount !== 1) {
        throw new Error('next authenticated MLS control block is unavailable')
      }
      const result = await this.withCryptoLock(() =>
        this.client.applyOrderedInboundMlsMembershipCommit(
          envelope.id,
          envelope.cursor,
          envelope.sendId,
          groupId,
          commit,
          expectedMembers,
          history.bytes,
        ),
      )
      if (
        result.receipt.envelopeId !== envelope.id
        || result.receipt.cursor !== envelope.cursor
        || result.receipt.sendId !== envelope.sendId
        || result.conversation.lastFinalizedEpoch !== inspection.epochAfter
        || result.group.epoch !== inspection.epochAfter
      ) {
        throw new Error('durable inbound MLS result differs from its mailbox Commit')
      }
      records[recordIndex] = result.conversation
      await this.publishCurrentDeliveryCapability(result.conversation)
      await this.transport.ackMlsMailbox(this.deviceId, [envelope.id])
      applied.push(result)
    }
    return applied
  }

  /** Apply owner-signed next-incarnation Welcomes before ordinary commits. */
  async reconcileInboundRecoveries(): Promise<JoinedMlsConversation[]> {
    const records = await this.withCryptoLock(() => this.client.localMlsConversations())
    const joined: JoinedMlsConversation[] = []
    for (const envelope of await this.allMembershipEnvelopes()) {
      const receipt = await this.withCryptoLock(() =>
        this.client.processedMlsControlEnvelope(envelope.id))
      if (receipt) continue
      const previous = records.find(record =>
        record.status === 'active'
        && record.request.genesis.conversationId === envelope.conversationId
        && record.request.genesis.incarnation + 1 === envelope.incarnation)
      if (!previous) continue
      const recovery = await this.transport.fetchMlsRecovery(
        envelope.conversationId!,
        envelope.incarnation!,
      )
      validateRecoveryStatement(recovery, previous, envelope)
      const groupId = decodeCanonicalBase64(
        recovery.plan.newGenesis.mlsGroupId,
        16,
        255,
      )
      const welcome = decodeCanonicalBase64(envelope.opaqueEnvelope, 1, 1024 * 1024)
      const inspection = await this.withCryptoLock(() =>
        this.client.inspectMlsWelcome(groupId, welcome))
      if (
        inspection.epoch !== 1
        || !equalBytes(inspection.mlsGroupId, groupId)
        || inspection.privateControlState.conversationId !== envelope.conversationId
        || inspection.privateControlState.incarnation !== envelope.incarnation
        || inspection.privateControlState.initialEpoch !== 1
        || inspection.privateControlState.height !== 0
        || inspection.privateControlState.epoch !== 1
      ) {
        throw new Error('MLS recovery Welcome differs from its signed next incarnation')
      }
      const expectedMembers = await this.withCryptoLock(() =>
        this.client.resolveMlsWelcomeClaims(inspection.claimedMembers))
      validateResolvedRoster(inspection.claimedMembers, expectedMembers)
      const result = await this.withCryptoLock(() =>
        this.client.joinMlsFromRecoveryWelcome(
          envelope.id,
          envelope.cursor,
          envelope.sendId,
          groupId,
          welcome,
          expectedMembers,
          recovery,
        ))
      if (
        result.group.epoch !== 1
        || result.conversation.status !== 'active'
        || result.conversation.request.genesis.conversationId !== envelope.conversationId
        || result.conversation.request.genesis.incarnation !== envelope.incarnation
        || result.conversation.recoveryDigest === undefined
      ) {
        throw new Error('durable MLS recovery differs from its signed statement')
      }
      await this.publishCurrentDeliveryCapability(result.conversation)
      await this.transport.ackMlsMailbox(this.deviceId, [envelope.id])
      joined.push(result)
    }
    return joined
  }

  async reconcileInboundApplicationMessages(): Promise<AppliedInboundMlsApplication[]> {
    const recipient = requireCanonicalAddress(this.selfAddress)
    const applied: AppliedInboundMlsApplication[] = []
    for (const mailbox of await this.allMlsEnvelopes()) {
      if (mailbox.deliveryKind !== 'anonymous') continue
      const existing = await this.withCryptoLock(() =>
        this.client.processedMlsApplicationEnvelope(mailbox.id),
      )
      if (existing) {
        if (
          existing.recordId !== `in:${mailbox.id}`
          || existing.messageId !== mailbox.sendId
          || String(existing.cursor) !== mailbox.cursor
        ) {
          throw new Error('MLS application replay differs from its durable receipt')
        }
        await this.transport.ackMlsMailbox(this.deviceId, [mailbox.id])
        continue
      }
      const envelope = decodeAnonymousEnvelope(mailbox.opaqueEnvelope)
      const inspection = await this.withCryptoLock(() =>
        this.client.inspectAnonymousMlsApplicationEnvelope(
          recipient,
          mailbox.sendId,
          envelope,
        ),
      )
      const senders = await this.withCryptoLock(() =>
        this.client.resolveMlsWelcomeClaims([inspection.claimedSender]),
      )
      if (senders.length !== 1) {
        throw new Error('MLS application sender did not resolve to one manifest device')
      }
      const result = await this.withCryptoLock(() =>
        this.client.applyAnonymousMlsApplicationEnvelope(
          mailbox.id,
          mailbox.cursor,
          mailbox.sendId,
          String(mailbox.serverTimestamp),
          recipient,
          envelope,
          senders[0],
        ),
      )
      if (
        result.message.recordId !== `in:${mailbox.id}`
        || result.message.messageId !== mailbox.sendId
        || result.message.conversationId.length !== 16
      ) {
        throw new Error('durable MLS application result differs from its mailbox envelope')
      }
      await this.transport.ackMlsMailbox(this.deviceId, [mailbox.id])
      applied.push(result)
    }
    return applied
  }

  async reconcile(): Promise<void> {
    await this.reconcilePendingGroupGeneses()
    await this.reconcilePendingMembershipChanges()
    await this.reconcilePendingAuthorityChanges()
    await this.reconcilePendingOwnerChanges()
    await this.reconcilePendingPolicyChanges()
    await this.reconcilePendingCloses()
    await this.reconcilePendingRecoveries()
    for (const conversation of await this.conversations()) {
      if (conversation.status === 'active') {
        await this.publishCurrentDeliveryCapability(conversation)
      }
    }
    await this.reconcileInboundRecoveries()
    await this.reconcileInboundMembershipCommits()
    await this.reconcilePendingApplicationMessages()
    await this.reconcileInboundApplicationMessages()
    await this.reconcilePendingOwnerChanges()
    await this.reconcilePendingPolicyChanges()
    await this.reconcilePendingCloses()
    await this.reconcilePendingRecoveries()
  }

  /**
   * Join locally first, then activate server delivery. If transport fails after
   * the durable join, a retry observes the exact existing group/epoch and
   * resumes only the server response and mailbox acknowledgement.
   */
  private async acceptVerifiedInvitation(
    pending: PendingMlsInvitation,
    verified: VerifiedMlsInvitation,
  ): Promise<AcceptedMlsInvitation> {
    validateInvitation(pending, Math.floor(Date.now() / 1000))
    validateVerifiedInvitation(pending, verified)
    const groupId = decodeCanonicalBase64(verified.mlsGroupId, 16, 255)
    const envelopes = await this.membershipEnvelopes(
      verified.conversationId,
      verified.incarnation,
    )
    if (envelopes.length !== 1) {
      throw new Error('MLS invitation must have exactly one control envelope for this device')
    }
    const welcome = decodeCanonicalBase64(envelopes[0].opaqueEnvelope, 1, 1024 * 1024)
    const resumed = await this.withCryptoLock(() =>
      this.client.mlsGroupState(groupId),
    ) !== null
    const historyPages = await this.controlHistory(
      verified.conversationId,
      verified.incarnation,
    )
    const joined = await this.withCryptoLock(() =>
      this.client.joinMlsFromWelcomeWithControlHistory(
        envelopes[0].id,
        envelopes[0].cursor,
        envelopes[0].sendId,
        groupId,
        welcome,
        verified.expectedMembers,
        historyPages,
      ),
    )
    const group = joined.group
    if (
      group.epoch !== verified.invitedEpoch
      || joined.conversation.request.genesis.conversationId !== verified.conversationId
      || joined.conversation.request.genesis.incarnation !== verified.incarnation
      || joined.conversation.lastFinalizedEpoch !== verified.invitedEpoch
    ) {
      throw new Error('MLS Welcome differs from authenticated invitation history')
    }
    const decision = await this.transport.respondMlsInvitation({
      conversationId: verified.conversationId,
      incarnation: verified.incarnation,
      accept: true,
    })
    if (decision.status !== 'active') {
      throw new Error('server did not activate the verified MLS invitation')
    }
    await this.publishCurrentDeliveryCapability(joined.conversation)
    await this.publishOwnerCandidateForRecord(joined.conversation)
    await this.transport.ackMlsMailbox(
      this.deviceId,
      envelopes.map((envelope) => envelope.id),
    )
    return { group, serverAccepted: true, resumed }
  }

  private async publishOwnerCandidateForRecord(
    conversation: LocalMlsConversationRecord,
  ): Promise<MlsOwnerCandidate> {
    const groupId = decodeCanonicalBase64(
      conversation.request.genesis.mlsGroupId,
      16,
      255,
    )
    const now = String(Math.floor(Date.now() / 1000))
    const candidate = await this.withCryptoLock(() =>
      this.client.ensureMlsOwnerCandidate(groupId, now))
    const local = requireCanonicalAddress(this.selfAddress)
    if (canonicalAccountAddress(candidate.account) !== canonicalAccountAddress(local)) {
      throw new Error('local MLS owner candidate is bound to a different account')
    }
    const entry = await this.withCryptoLock(() =>
      this.client.createMlsOwnerCandidateMessage(groupId, now))
    if (entry) await this.deliverApplicationEntry(entry)
    return candidate
  }

  private async publishOwnerApprovalRequest(groupId: Uint8Array): Promise<void> {
    const entry = await this.withCryptoLock(() =>
      this.client.createMlsOwnerApprovalRequestMessage(groupId))
    if (entry) await this.deliverApplicationEntry(entry)
  }

  private async controlHistory(
    conversationId: string,
    incarnation: number,
  ): Promise<Uint8Array[]> {
    let afterHeight = '0'
    const pages: Uint8Array[] = []
    for (let pageIndex = 0; pageIndex < MAX_CONTROL_HISTORY_PAGES; pageIndex += 1) {
      const page = await this.transport.fetchMlsControlHistory(
        conversationId,
        incarnation,
        afterHeight,
        64,
      )
      if (!(page.bytes instanceof Uint8Array) || page.bytes.length < 2 || page.bytes.length > 8 * 1024 * 1024) {
        throw new Error('MLS control-history page is outside the client size bound')
      }
      if (page.entryCount === 0) return pages
      pages.push(page.bytes)
      if (page.entryCount < 64) return pages
      if (!page.nextHeight) {
        throw new Error('full MLS control-history page omitted its next cursor')
      }
      if (BigInt(page.nextHeight) <= BigInt(afterHeight)) {
        throw new Error('MLS control-history pagination did not advance')
      }
      afterHeight = page.nextHeight
    }
    throw new Error('MLS control history exceeded the bounded client scan')
  }

  private async membershipEnvelopes(
    conversationId: string,
    incarnation: number,
  ): Promise<MlsMailboxEnvelope[]> {
    return (await this.allMembershipEnvelopes()).filter(
      (envelope) =>
        envelope.conversationId === conversationId
        && envelope.incarnation === incarnation,
    )
  }

  private async allMembershipEnvelopes(): Promise<MlsMailboxEnvelope[]> {
    return (await this.allMlsEnvelopes()).filter(
      envelope => envelope.deliveryKind === 'membership_control',
    )
  }

  private async allMlsEnvelopes(): Promise<MlsMailboxEnvelope[]> {
    let after: string | undefined
    const envelopes: MlsMailboxEnvelope[] = []
    for (let pageIndex = 0; pageIndex < MAX_MAILBOX_PAGES; pageIndex += 1) {
      const page = await this.transport.drainMlsMailbox(this.deviceId, after, 256)
      for (const envelope of page.envelopes) {
        validateMailboxEnvelope(envelope)
        envelopes.push(envelope)
      }
      if (!page.nextCursor || page.nextCursor === after || page.envelopes.length < 256) {
        return envelopes
      }
      after = page.nextCursor
    }
    throw new Error('MLS mailbox exceeded the bounded client scan')
  }

  private async requireActiveConversation(
    conversationId: string,
  ): Promise<LocalMlsConversationRecord> {
    if (!isUuid(conversationId)) throw new Error('invalid MLS conversation id')
    const records = await this.conversations()
    const conversation = records.find(record =>
      record.status === 'active'
      && record.request.genesis.conversationId === conversationId)
    if (!conversation) throw new Error('active local MLS conversation is unavailable')
    validateLocalGenesisRecord(conversation)
    return conversation
  }

  private async publishCurrentDeliveryCapability(
    conversation: LocalMlsConversationRecord,
  ): Promise<void> {
    if (!this.selfAddress) return
    const recipient = requireCanonicalAddress(this.selfAddress)
    if (!conversation.currentRoster.some(
      member => canonicalAccountAddress(member.address) === canonicalAccountAddress(recipient),
    )) return
    const publicationKey =
      `${conversation.request.genesis.incarnation}:${conversation.lastFinalizedEpoch}`
    if (
      this.publishedCapabilityEpochs.get(conversation.request.genesis.conversationId)
      === publicationKey
    ) return
    const groupId = decodeCanonicalBase64(
      conversation.request.genesis.mlsGroupId,
      16,
      255,
    )
    const derived = await this.withCryptoLock(() =>
      this.client.deriveMlsDeliveryCapability(
        groupId,
        conversation.request.genesis.conversationId,
        String(conversation.request.genesis.incarnation),
        recipient,
      ) as Promise<DerivedMlsDeliveryCapability>,
    )
    if (derived.verifierHash.length !== 32 || derived.capability.length !== 16) {
      throw new Error('shared MLS capability derivation returned invalid key material')
    }
    if (derived.epoch !== conversation.lastFinalizedEpoch) {
      throw new Error('shared MLS capability is bound to a stale group epoch')
    }
    await this.transport.publishMlsDeliveryCapability({
      protocolVersion: MLS_PROTOCOL_VERSION,
      conversationId: conversation.request.genesis.conversationId,
      incarnation: conversation.request.genesis.incarnation,
      epoch: derived.epoch,
      capabilityKind: 'group',
      capabilityHash: encodeHex(derived.verifierHash),
      policySequence: 1,
    })
    this.publishedCapabilityEpochs.set(
      conversation.request.genesis.conversationId,
      publicationKey,
    )
  }

  private async deliverApplicationEntry(initial: MlsOutboxEntry): Promise<void> {
    let entry = initial
    for (const recipientText of entry.expectedRecipients) {
      const existing = entry.deliveries.find(delivery => delivery.recipient === recipientText)
      if (existing?.delivered) continue
      const recipient = parseAccountAddress(recipientText)
      if (!recipient?.server || canonicalAccountAddress(recipient) !== recipientText) {
        throw new MlsSendError(
          'recipient',
          new Error('durable MLS recipient is not a canonical federated address'),
        )
      }
      if (!existing) {
        const derived = await this.withCryptoLock(() =>
            this.client.deriveMlsDeliveryCapability(
              Uint8Array.from(entry.mlsGroupId),
              bytesToUuid(entry.conversationId),
              String(entry.incarnation),
              recipient,
            ) as Promise<DerivedMlsDeliveryCapability>,
          )
          .catch(cause => { throw new MlsSendError('capability', cause) })
        if (derived.epoch !== entry.epoch || derived.capability.length !== 16) {
          throw new MlsSendError(
            'capability_binding',
            new Error('MLS send capability differs from the durable ciphertext epoch'),
          )
        }
        const packages = await this.fetchVerifiedKeyPackages(
            recipient,
            Uint8Array.from(derived.capability),
          )
          .catch(cause => { throw new MlsSendError('key_packages', cause) })
        const staged = await this.withCryptoLock(() =>
            this.client.stageMlsApplicationDelivery(
              entry.sendId,
              recipient,
              Uint8Array.from(derived.capability),
              packages,
              String(Math.floor(Date.now() / 1000)),
            ),
          )
          .catch(cause => { throw new MlsSendError('envelope_staging', cause) })
        entry = staged.entry
      }
      const submission = await this.withCryptoLock(() =>
          this.client.noteMlsApplicationDeliveryAttempt(entry.sendId, recipientText),
        )
        .catch(cause => { throw new MlsSendError('outbox_attempt', cause) })
      const response = await this.transport.submitAnonymousMlsMessage(submission)
        .then(value => requireAnonymousDeliveryResponse(value, submission.envelopes.length))
        .catch(cause => { throw new MlsSendError('submission', cause) })
      await this.withCryptoLock(() =>
          this.client.markMlsApplicationRecipientDelivered(
            entry.sendId,
            recipientText,
            response.deduplicated,
          ),
        )
        .catch(cause => { throw new MlsSendError('receipt', cause) })
    }
  }

  private async publishPreparedGenesis(
    record: LocalMlsConversationRecord,
  ): Promise<LocalMlsConversationRecord> {
    validateLocalGenesisRecord(record)
    if (record.status !== 'pending_genesis') {
      throw new Error('only a pending MLS genesis can be published')
    }
    const response = requireCreateConversationResponse(
      await this.transport.createMlsConversation(record.request),
      record.request.genesis.conversationId,
    )
    const active = await this.withCryptoLock(() =>
      this.client.markMlsGroupGenesisPublished(
        response.conversationId,
        response.genesisHash,
      ),
    )
    validateLocalGenesisRecord(active)
    if (
      active.status !== 'active'
      || active.serverGenesisHash !== response.genesisHash
      || active.request.genesis.conversationId !== response.conversationId
    ) {
      throw new Error('durable MLS genesis acknowledgement differs from the server response')
    }
    return active
  }

  private async publishPendingMembershipChange(
    control: PendingMlsMembershipChange,
  ): Promise<FinalizedMlsMembershipChange> {
    const groupId = Uint8Array.from(control.mlsGroupId)
    validatePendingMembershipChange(control, groupId)
    for (const delivery of control.deliveries) {
      await this.transport.stageMlsMembershipDelivery(delivery)
    }
    const request = control.finalRequest ?? await (async () => {
      const quorumCertificate = await this.transport.collectMlsOrderingVotes(
        control.voteRequest,
      )
      return this.withCryptoLock(() =>
        this.client.buildMlsMembershipCommitRequest(groupId, quorumCertificate),
      )
    })()
    const acknowledgement = requireControlBlockResponse(
      await this.transport.commitMlsControlBlock(request),
      control,
    )
    const finalized = await this.withCryptoLock(() =>
      this.client.finalizeMlsMembershipChange(groupId, acknowledgement),
    )
    if (
      finalized.group.epoch !== control.voteRequest.block.epochAfter
      || finalized.conversation.lastFinalizedHeight
        !== control.voteRequest.block.height
      || finalized.conversation.lastBlockHash !== acknowledgement.blockHash
    ) {
      throw new Error('durable MLS membership state differs from its finalized block')
    }
    return finalized
  }

  private async publishPendingAuthorityChange(
    control: PendingMlsAuthorityChange,
  ): Promise<FinalizedMlsAuthorityChange> {
    const groupId = Uint8Array.from(control.mlsGroupId)
    validatePendingAuthorityChange(control, groupId)
    for (const delivery of control.deliveries) {
      await this.transport.stageMlsMembershipDelivery(delivery)
    }
    let request = control.finalRequest
    if (!request) {
      let nextVoteRequest = control.newVoteRequest
      if (!nextVoteRequest) {
        const previousCertificate = await this.transport.collectMlsOrderingVotes(
          control.voteRequest,
        )
        nextVoteRequest = await this.withCryptoLock(() =>
          this.client.recordMlsAuthorityPreviousQuorum(groupId, previousCertificate))
      }
      const newCertificate = await this.transport.collectMlsOrderingVotes(nextVoteRequest)
      request = await this.withCryptoLock(() =>
        this.client.buildMlsAuthorityCommitRequest(groupId, newCertificate))
    }
    const acknowledgement = requireControlBlockResponse(
      await this.transport.commitMlsControlBlock(request),
      control,
    )
    const finalized = await this.withCryptoLock(() =>
      this.client.finalizeMlsAuthorityChange(groupId, acknowledgement))
    if (
      finalized.group.epoch !== control.voteRequest.block.epochAfter
      || finalized.conversation.currentAuthoritySet.sequence
        !== control.authorityChange.nextAuthoritySet.sequence
      || finalized.conversation.lastBlockHash !== acknowledgement.blockHash
    ) {
      throw new Error('durable MLS authority state differs from its finalized block')
    }
    return finalized
  }

  private async publishPendingOwnerChange(
    control: PendingMlsOwnerChange,
  ): Promise<FinalizedMlsOwnerChange> {
    const groupId = Uint8Array.from(control.mlsGroupId)
    validatePendingOwnerChange(control, groupId)
    for (const delivery of control.deliveries) {
      await this.transport.stageMlsMembershipDelivery(delivery)
    }
    let request = control.finalRequest
    if (!request) {
      const certificate = await this.transport.collectMlsOrderingVotes(control.voteRequest)
      request = await this.withCryptoLock(() =>
        this.client.buildMlsOwnerCommitRequest(groupId, certificate))
    }
    const acknowledgement = requireControlBlockResponse(
      await this.transport.commitMlsControlBlock(request),
      control,
    )
    const finalized = await this.withCryptoLock(() =>
      this.client.finalizeMlsOwnerChange(groupId, acknowledgement))
    if (
      finalized.group.epoch !== control.voteRequest.block.epochAfter
      || finalized.conversation.currentOwnerSet.sequence
        !== control.ownerChange.nextOwnerSet.sequence
      || finalized.conversation.lastBlockHash !== acknowledgement.blockHash
    ) {
      throw new Error('durable MLS owner state differs from its finalized block')
    }
    return finalized
  }

  private async publishPendingClose(
    control: PendingMlsClose,
  ): Promise<FinalizedMlsClose> {
    const groupId = Uint8Array.from(control.mlsGroupId)
    validatePendingClose(control, groupId)
    for (const delivery of control.deliveries) {
      await this.transport.stageMlsMembershipDelivery(delivery)
    }
    let request = control.finalRequest
    if (!request) {
      const certificate = await this.transport.collectMlsOrderingVotes(control.voteRequest)
      request = await this.withCryptoLock(() =>
        this.client.buildMlsCloseCommitRequest(groupId, certificate))
    }
    const acknowledgement = requireControlBlockResponse(
      await this.transport.commitMlsControlBlock(request),
      control,
    )
    const finalized = await this.withCryptoLock(() =>
      this.client.finalizeMlsClose(groupId, acknowledgement))
    if (
      finalized.group.epoch !== control.voteRequest.block.epochAfter
      || finalized.conversation.status !== 'closed'
      || finalized.conversation.lastBlockHash !== acknowledgement.blockHash
    ) {
      throw new Error('durable MLS close state differs from its finalized block')
    }
    return finalized
  }

  private async publishPendingPolicyChange(
    control: PendingMlsPolicyChange,
  ): Promise<FinalizedMlsPolicyChange> {
    const groupId = Uint8Array.from(control.mlsGroupId)
    validatePendingPolicyChange(control, groupId)
    for (const delivery of control.deliveries) {
      await this.transport.stageMlsMembershipDelivery(delivery)
    }
    let request = control.finalRequest
    if (!request) {
      const certificate = await this.transport.collectMlsOrderingVotes(control.voteRequest)
      request = await this.withCryptoLock(() =>
        this.client.buildMlsPolicyCommitRequest(groupId, certificate))
    }
    const acknowledgement = requireControlBlockResponse(
      await this.transport.commitMlsControlBlock(request),
      control,
    )
    const finalized = await this.withCryptoLock(() =>
      this.client.finalizeMlsPolicyChange(groupId, acknowledgement))
    if (
      finalized.group.epoch !== control.voteRequest.block.epochAfter
      || finalized.conversation.lastBlockHash !== acknowledgement.blockHash
      || (
        control.nextAuthorizationPolicy
        && finalized.conversation.currentAuthorizationPolicy.sequence
          !== control.nextAuthorizationPolicy.sequence
      )
      || (
        control.nextCryptographicPolicy
        && finalized.conversation.currentCryptographicPolicy.sequence
          !== control.nextCryptographicPolicy.sequence
      )
    ) {
      throw new Error('durable MLS policy state differs from its finalized block')
    }
    await this.publishCurrentDeliveryCapability(finalized.conversation)
    return finalized
  }

  private async publishPendingRecovery(
    control: PendingMlsRecovery,
  ): Promise<FinalizedMlsRecovery> {
    const oldGroupId = Uint8Array.from(control.mlsGroupId)
    validatePendingRecovery(
      control,
      oldGroupId,
      Uint8Array.from(control.newMlsGroupId),
    )
    const acknowledgement = requireRecoveryResponse(
      await this.transport.recoverMlsConversation(control.request),
      control,
    )
    const finalized = await this.withCryptoLock(() =>
      this.client.finalizeMlsGroupRecovery(oldGroupId, acknowledgement))
    if (
      finalized.group.epoch !== 1
      || finalized.conversation.status !== 'active'
      || finalized.conversation.request.genesis.incarnation !== acknowledgement.incarnation
      || finalized.conversation.recoveryDigest !== acknowledgement.recoveryDigest
      || finalized.archivedIncarnation.status !== 'read_only'
      || finalized.archivedIncarnation.request.genesis.incarnation
        !== acknowledgement.previousIncarnation
    ) {
      throw new Error('durable MLS recovery differs from its server acknowledgement')
    }
    return finalized
  }
}

interface BrowserCrypto {
  randomUUID(): string
  getRandomValues<T extends ArrayBufferView | null>(array: T): T
}

function requireBrowserCrypto(): BrowserCrypto {
  const value = globalThis.crypto
  if (
    !value
    || typeof value.randomUUID !== 'function'
    || typeof value.getRandomValues !== 'function'
  ) {
    throw new Error('secure browser randomness is unavailable')
  }
  return value
}

function requireAuthorityDomains(authorityDomains: string[]): string[] {
  if (!Array.isArray(authorityDomains) || authorityDomains.length < 1 || authorityDomains.length > 64) {
    throw new Error('MLS group genesis requires 1-64 ordering authorities')
  }
  const domains = [...authorityDomains].sort()
  for (let index = 0; index < domains.length; index += 1) {
    const domain = domains[index]
    if (
      typeof domain !== 'string'
      || domain.length < 1
      || domain.length > 253
      || domain.trim() !== domain
      || domain.toLowerCase() !== domain
      || (index > 0 && domains[index - 1] === domain)
    ) {
      throw new Error('MLS ordering authority domains must be canonical and unique')
    }
  }
  return domains
}

function validatePreparedGenesis(
  prepared: PreparedMlsGroupGenesis,
  conversationId: string,
  groupId: Uint8Array,
): void {
  if (
    !prepared
    || prepared.group.epoch !== 0
    || !equalBytes(prepared.group.mlsGroupId, groupId)
    || prepared.conversation.request.genesis.conversationId !== conversationId
    || prepared.conversation.request.genesis.mlsGroupId !== encodeBase64(groupId)
  ) {
    throw new Error('prepared MLS group differs from the requested genesis')
  }
  validateLocalGenesisRecord(prepared.conversation)
}

function validateLocalGenesisRecord(record: LocalMlsConversationRecord): void {
  const genesis = record?.request?.genesis
  const recovered = (genesis?.incarnation ?? 0) > 1
  if (
    !genesis
    || !isUuid(genesis.conversationId)
    || genesis.protocolVersion !== MLS_PROTOCOL_VERSION
    || !Number.isSafeInteger(genesis.incarnation)
    || genesis.incarnation < 1
    || genesis.kind !== 'group'
    || genesis.initialEpoch !== (recovered ? 1 : 0)
    || genesis.memberCount !== record.request.members.length
    || genesis.memberCount < 1
    || genesis.memberCount > 1000
    || !Number.isSafeInteger(record.lastFinalizedHeight)
    || record.lastFinalizedHeight < 0
    || !Number.isSafeInteger(record.lastFinalizedEpoch)
    || record.lastFinalizedEpoch < 0
    || record.currentRoster.length < 1
    || record.currentRoster.length > 1000
    || record.currentAuthoritySet.authorities.length < 1
    || record.currentOwnerSet.owners.length < 1
    || !isAuthorizationPolicy(record.genesisAuthorizationPolicy)
    || !isAuthorizationPolicy(record.currentAuthorizationPolicy)
    || !isCryptographicPolicy(record.genesisCryptographicPolicy)
    || !isCryptographicPolicy(record.currentCryptographicPolicy)
    || record.genesisAuthorizationPolicy.sequence !== 1
    || record.genesisCryptographicPolicy.sequence !== 1
    || record.currentAuthorizationPolicy.sequence > record.lastFinalizedHeight + 1
    || record.currentCryptographicPolicy.sequence > record.lastFinalizedHeight + 1
    || (
      record.lastFinalizedHeight === 0
      && (
        record.lastFinalizedEpoch !== genesis.initialEpoch
        || record.lastBlockHash !== undefined
      )
    )
    || (
      record.lastFinalizedHeight > 0
      && !isSha256(record.lastBlockHash)
    )
    || record.lastFinalizedEpoch !== genesis.initialEpoch + record.lastFinalizedHeight
    || !['pending_genesis', 'active', 'read_only', 'closed'].includes(record.status)
    || (
      record.status === 'pending_genesis'
      && (recovered || record.serverGenesisHash !== undefined)
    )
    || (
      (record.status === 'active' || record.status === 'read_only' || record.status === 'closed')
      && !isSha256(record.serverGenesisHash)
    )
    || (recovered !== isSha256(record.recoveryDigest))
  ) {
    throw new Error('invalid durable MLS group genesis record')
  }
  decodeCanonicalBase64(genesis.mlsGroupId, 16, 255)
}

function isAuthorizationPolicy(
  value: MlsGroupAuthorizationPolicy | undefined,
): value is MlsGroupAuthorizationPolicy {
  return Boolean(
    value
    && value.policyVersion === 1
    && Number.isSafeInteger(value.sequence)
    && value.sequence >= 1
    && [1, 2].includes(value.applicationSenders),
  )
}

function isCryptographicPolicy(
  value: MlsGroupCryptographicPolicy | undefined,
): value is MlsGroupCryptographicPolicy {
  return Boolean(
    value
    && value.policyVersion === 1
    && Number.isSafeInteger(value.sequence)
    && value.sequence >= 1
    && value.suite === 2
    && value.requiredPrivateControlExtension === 0xff4b
    && value.maximumPastEpochs === 2
    && value.anonymousDeliveryRequired === true
    && value.paddingBlockBytes === 1024
    && Number.isSafeInteger(value.maximumApplicationPlaintextBytes)
    && value.maximumApplicationPlaintextBytes >= 1024
    && value.maximumApplicationPlaintextBytes <= 1024 * 1024,
  )
}

function validateVerifiedKeyPackage(
  keyPackage: VerifiedMlsKeyPackage,
  expectedAccount: string,
): void {
  if (
    !keyPackage
    || !Number.isSafeInteger(keyPackage.wire?.deviceId)
    || keyPackage.wire.deviceId < 1
    || keyPackage.wire.deviceId > 127
    || keyPackage.credential?.credentialIdentity
      !== `${expectedAccount}#${keyPackage.wire.deviceId}`
    || keyPackage.credential.credentialPublicKey.length !== 65
  ) {
    throw new Error('transparency-verified recovery KeyPackage has an invalid device binding')
  }
}

function validatePendingRecovery(
  control: PendingMlsRecovery,
  expectedOldGroupId: Uint8Array,
  expectedNewGroupId: Uint8Array,
): void {
  const plan = control?.request?.recovery?.plan
  const genesis = plan?.newGenesis
  if (
    !control
    || !equalBytes(control.mlsGroupId, expectedOldGroupId)
    || !equalBytes(control.newMlsGroupId, expectedNewGroupId)
    || equalBytes(control.mlsGroupId, Uint8Array.from(control.newMlsGroupId))
    || !isSha256(control.commitHash)
    || !plan
    || plan.protocolVersion !== MLS_PROTOCOL_VERSION
    || !isUuid(plan.conversationId)
    || !isUuid(plan.proposalId)
    || !Number.isSafeInteger(plan.previousIncarnation)
    || plan.previousIncarnation < 1
    || genesis?.conversationId !== plan.conversationId
    || genesis.incarnation !== plan.previousIncarnation + 1
    || genesis.initialEpoch !== 1
    || genesis.mlsGroupId !== encodeBase64(expectedNewGroupId)
    || genesis.memberCount !== control.request.members.length
    || control.request.members.length < 1
    || control.request.members.length > 1000
    || !Array.isArray(control.request.deliveries)
    || control.request.deliveries.length !== plan.participantDomains.length
    || !Array.isArray(plan.deliveries)
    || plan.deliveries.length !== plan.participantDomains.length
  ) {
    throw new Error('invalid durable MLS incarnation recovery')
  }
}

function validateRecoveryStatement(
  recovery: MlsIncarnationRecovery,
  previous: LocalMlsConversationRecord,
  envelope: MlsMailboxEnvelope,
): void {
  const plan = recovery?.plan
  if (
    !plan
    || plan.protocolVersion !== MLS_PROTOCOL_VERSION
    || plan.conversationId !== previous.request.genesis.conversationId
    || plan.conversationId !== envelope.conversationId
    || plan.previousIncarnation !== previous.request.genesis.incarnation
    || plan.newGenesis.incarnation !== envelope.incarnation
    || plan.newGenesis.incarnation !== plan.previousIncarnation + 1
    || plan.newGenesis.initialEpoch !== 1
    || plan.newGenesis.memberCount !== previous.currentRoster.length
    || plan.previousHeight !== previous.lastFinalizedHeight
    || plan.previousEpoch !== previous.lastFinalizedEpoch
    || plan.previousBlockHash !== previous.lastBlockHash
  ) {
    throw new Error('server returned an MLS recovery for a different durable head')
  }
  decodeCanonicalBase64(plan.newGenesis.mlsGroupId, 16, 255)
}

function validateResolvedRoster(
  claimed: Array<{ credentialIdentity: string; credentialPublicKey: number[] }>,
  verified: VerifiedMlsCredential[],
): void {
  if (
    verified.length !== claimed.length
    || verified.some((member, index) => {
      const claim = claimed[index]
      return member.credentialIdentity !== claim.credentialIdentity
        || !equalBytes(member.credentialPublicKey, Uint8Array.from(claim.credentialPublicKey))
    })
  ) {
    throw new Error('shared verifier returned a roster different from the inspected MLS state')
  }
}

function validatePendingMembershipChange(
  control: PendingMlsMembershipChange,
  expectedGroupId: Uint8Array,
): void {
  const block = control?.voteRequest?.block
  if (
    !control
    || !equalBytes(control.mlsGroupId, expectedGroupId)
    || !isSha256(control.commitHash)
    || !Array.isArray(control.nextRoster)
    || control.nextRoster.length < 2
    || control.nextRoster.length > 1000
    || !Array.isArray(control.deliveries)
    || control.deliveries.length < 1
    || !block
    || !isUuid(block.conversationId)
    || block.conversationId !== control.transition?.conversationId
    || block.incarnation !== control.transition?.incarnation
    || !isUuid(control.transition?.proposalId)
    || !Number.isSafeInteger(block.height)
    || block.height < 1
    || !Number.isSafeInteger(block.epochBefore)
    || block.epochBefore < 0
    || !Number.isSafeInteger(block.epochAfter)
    || block.epochAfter !== block.epochBefore + 1
  ) {
    throw new Error('invalid durable MLS membership control record')
  }
}

function validatePendingAuthorityChange(
  control: PendingMlsAuthorityChange,
  expectedGroupId: Uint8Array,
): void {
  const block = control?.voteRequest?.block
  const change = control?.authorityChange
  if (
    !control
    || !equalBytes(control.mlsGroupId, expectedGroupId)
    || !isSha256(control.commitHash)
    || !Array.isArray(control.deliveries)
    || control.deliveries.length < 1
    || !block
    || !change
    || !isUuid(block.conversationId)
    || block.conversationId !== change.deliveryTransition?.conversationId
    || block.incarnation !== change.deliveryTransition?.incarnation
    || !isUuid(change.deliveryTransition?.proposalId)
    || !Number.isSafeInteger(change.nextAuthoritySet?.sequence)
    || change.nextAuthoritySet.sequence < 2
    || !Array.isArray(change.nextAuthoritySet.authorities)
    || change.nextAuthoritySet.authorities.length < 1
    || change.nextAuthoritySet.authorities.length > 64
    || block.epochAfter !== block.epochBefore + 1
  ) {
    throw new Error('invalid durable MLS authority control record')
  }
}

function validatePendingOwnerChange(
  control: PendingMlsOwnerChange,
  expectedGroupId: Uint8Array,
): void {
  const block = control?.voteRequest?.block
  const change = control?.ownerChange
  if (
    !control
    || !equalBytes(control.mlsGroupId, expectedGroupId)
    || !isSha256(control.commitHash)
    || !Array.isArray(control.nextRoster)
    || control.nextRoster.length < 1
    || control.nextRoster.length > 1000
    || !Array.isArray(control.deliveries)
    || control.deliveries.length < 1
    || !block
    || !change
    || !isUuid(block.conversationId)
    || block.conversationId !== change.deliveryTransition?.conversationId
    || block.incarnation !== change.deliveryTransition?.incarnation
    || !isUuid(change.deliveryTransition?.proposalId)
    || !Number.isSafeInteger(change.nextOwnerSet?.sequence)
    || change.nextOwnerSet.sequence < 2
    || !Array.isArray(change.nextOwnerSet.owners)
    || change.nextOwnerSet.owners.length < 1
    || change.nextOwnerSet.owners.length > 1024
    || block.epochAfter !== block.epochBefore + 1
  ) {
    throw new Error('invalid durable MLS owner control record')
  }
}

function validatePendingClose(
  control: PendingMlsClose,
  expectedGroupId: Uint8Array,
): void {
  const block = control?.voteRequest?.block
  const transition = control?.transition
  if (
    !control
    || !equalBytes(control.mlsGroupId, expectedGroupId)
    || !isSha256(control.commitHash)
    || !Array.isArray(control.currentRoster)
    || control.currentRoster.length < 1
    || control.currentRoster.length > 1000
    || !Array.isArray(control.deliveries)
    || control.deliveries.length < 1
    || !block
    || !transition
    || !isUuid(block.conversationId)
    || block.conversationId !== transition.conversationId
    || block.incarnation !== transition.incarnation
    || !isUuid(transition.proposalId)
    || block.epochAfter !== block.epochBefore + 1
  ) {
    throw new Error('invalid durable MLS close control record')
  }
}

function validatePendingPolicyChange(
  control: PendingMlsPolicyChange,
  expectedGroupId: Uint8Array,
): void {
  const block = control?.voteRequest?.block
  const transition = control?.transition
  const authorization = control?.nextAuthorizationPolicy
  const cryptographic = control?.nextCryptographicPolicy
  if (
    !control
    || !equalBytes(control.mlsGroupId, expectedGroupId)
    || !isSha256(control.commitHash)
    || !Array.isArray(control.currentRoster)
    || control.currentRoster.length < 1
    || control.currentRoster.length > 1000
    || !Array.isArray(control.deliveries)
    || control.deliveries.length < 1
    || !block
    || !transition
    || !isUuid(block.conversationId)
    || block.conversationId !== transition.conversationId
    || block.incarnation !== transition.incarnation
    || !isUuid(transition.proposalId)
    || block.epochAfter !== block.epochBefore + 1
    || Boolean(authorization) === Boolean(cryptographic)
    || (
      authorization
      && (
        authorization.policyVersion !== 1
        || !Number.isSafeInteger(authorization.sequence)
        || authorization.sequence < 2
        || ![1, 2].includes(authorization.applicationSenders)
      )
    )
    || (
      cryptographic
      && (
        cryptographic.policyVersion !== 1
        || !Number.isSafeInteger(cryptographic.sequence)
        || cryptographic.sequence < 2
        || cryptographic.suite !== 2
        || cryptographic.maximumPastEpochs !== 2
        || cryptographic.anonymousDeliveryRequired !== true
        || cryptographic.paddingBlockBytes !== 1024
        || !Number.isSafeInteger(cryptographic.maximumApplicationPlaintextBytes)
        || cryptographic.maximumApplicationPlaintextBytes < 1024
        || cryptographic.maximumApplicationPlaintextBytes > 1024 * 1024
      )
    )
  ) {
    throw new Error('invalid durable MLS policy control record')
  }
}

function requireControlBlockResponse(
  value: unknown,
  control:
    | PendingMlsMembershipChange
    | PendingMlsAuthorityChange
    | PendingMlsOwnerChange
    | PendingMlsClose
    | PendingMlsPolicyChange,
): {
  conversationId: string
  incarnation: number
  height: number
  epoch: number
  blockHash: string
  idempotent: boolean
} {
  const block = control.voteRequest.block
  if (
    typeof value !== 'object'
    || value === null
    || !('conversationId' in value)
    || value.conversationId !== block.conversationId
    || !('incarnation' in value)
    || value.incarnation !== block.incarnation
    || !('height' in value)
    || value.height !== block.height
    || !('epoch' in value)
    || value.epoch !== block.epochAfter
    || !('blockHash' in value)
    || !isSha256(value.blockHash)
    || !('idempotent' in value)
    || typeof value.idempotent !== 'boolean'
  ) {
    throw new Error('server returned an invalid MLS control-block acknowledgement')
  }
  return value as {
    conversationId: string
    incarnation: number
    height: number
    epoch: number
    blockHash: string
    idempotent: boolean
  }
}

function requireRecoveryResponse(
  value: unknown,
  control: PendingMlsRecovery,
): {
  conversationId: string
  previousIncarnation: number
  incarnation: number
  recoveryDigest: string
  status: 'active'
} {
  const plan = control.request.recovery.plan
  if (
    typeof value !== 'object'
    || value === null
    || !('conversationId' in value)
    || value.conversationId !== plan.conversationId
    || !('previousIncarnation' in value)
    || value.previousIncarnation !== plan.previousIncarnation
    || !('incarnation' in value)
    || value.incarnation !== plan.newGenesis.incarnation
    || !('recoveryDigest' in value)
    || !isSha256(value.recoveryDigest)
    || !('status' in value)
    || value.status !== 'active'
  ) {
    throw new Error('server returned an invalid MLS recovery acknowledgement')
  }
  return value as {
    conversationId: string
    previousIncarnation: number
    incarnation: number
    recoveryDigest: string
    status: 'active'
  }
}

function requireCreateConversationResponse(
  value: unknown,
  expectedConversationId: string,
): {
  conversationId: string
  incarnation: number
  genesisHash: string
  idempotent: boolean
} {
  if (
    typeof value !== 'object'
    || value === null
    || !('conversationId' in value)
    || value.conversationId !== expectedConversationId
    || !('incarnation' in value)
    || value.incarnation !== 1
    || !('genesisHash' in value)
    || !isSha256(value.genesisHash)
    || !('idempotent' in value)
    || typeof value.idempotent !== 'boolean'
  ) {
    throw new Error('server returned an invalid MLS conversation genesis acknowledgement')
  }
  return value as {
    conversationId: string
    incarnation: number
    genesisHash: string
    idempotent: boolean
  }
}

function isSha256(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)
}

function requireKeyPackageCount(value: unknown, deviceId: number): MlsKeyPackageCount {
  if (
    typeof value !== 'object'
    || value === null
    || !('deviceId' in value)
    || !('available' in value)
    || value.deviceId !== deviceId
    || typeof value.available !== 'number'
    || !Number.isInteger(value.available)
    || value.available < 0
    || value.available > 100_000
  ) {
    throw new Error('invalid MLS KeyPackage count response')
  }
  return value as MlsKeyPackageCount
}

function validateInvitation(invitation: PendingMlsInvitation, now: number): void {
  if (
    !isUuid(invitation.conversationId)
    || !Number.isSafeInteger(invitation.incarnation)
    || invitation.incarnation < 1
    || !Number.isSafeInteger(invitation.invitedEpoch)
    || invitation.invitedEpoch < 1
    || !Number.isSafeInteger(invitation.expiresAt)
    || invitation.expiresAt <= now
  ) {
    throw new Error('invalid or expired MLS invitation')
  }
  decodeCanonicalBase64(invitation.mlsGroupId, 16, 255)
}

function validateInvitationFeedback(feedback: MlsInvitationFeedback): void {
  if (
    feedback.protocolVersion !== MLS_PROTOCOL_VERSION
    || !isUuid(feedback.conversationId)
    || !Number.isSafeInteger(feedback.incarnation)
    || feedback.incarnation < 1
    || !Number.isSafeInteger(feedback.invitedEpoch)
    || feedback.invitedEpoch < 1
    || !Number.isSafeInteger(feedback.decidedAt)
    || feedback.decidedAt < 0
    || (feedback.decision !== 'rejected' && feedback.decision !== 'expired')
  ) {
    throw new Error('invalid MLS invitation feedback')
  }
  requireCanonicalAddress(feedback.member)
}

function validateVerifiedInvitation(
  pending: PendingMlsInvitation,
  verified: VerifiedMlsInvitation,
): void {
  if (
    verified.conversationId !== pending.conversationId
    || verified.incarnation !== pending.incarnation
    || verified.mlsGroupId !== pending.mlsGroupId
    || verified.invitedEpoch !== pending.invitedEpoch
    || verified.expectedMembers.length < 1
    || verified.expectedMembers.length > 1000
  ) {
    throw new Error('authenticated MLS invitation evidence differs from the pending invitation')
  }
  const identities = new Set<string>()
  for (const member of verified.expectedMembers) {
    if (
      member.credentialIdentity.trim() !== member.credentialIdentity
      || member.credentialIdentity.length < 1
      || member.credentialIdentity.length > 512
      || identities.has(member.credentialIdentity)
      || member.credentialPublicKey.length !== 65
    ) {
      throw new Error('invalid transparency-verified MLS roster')
    }
    identities.add(member.credentialIdentity)
  }
}

function validateMailboxEnvelope(envelope: MlsMailboxEnvelope): void {
  if (
    !isUuid(envelope.id)
    || !isUuid(envelope.sendId)
    || !/^[1-9][0-9]*$/.test(envelope.cursor)
    || !Number.isSafeInteger(envelope.serverTimestamp)
  ) {
    throw new Error('invalid MLS mailbox envelope')
  }
  decodeCanonicalBase64(envelope.opaqueEnvelope, 1, 1024 * 1024)
}

function decodeCanonicalBase64(value: string, minimum: number, maximum: number): Uint8Array {
  if (typeof value !== 'string' || value.length > Math.ceil(maximum / 3) * 4) {
    throw new Error('invalid MLS base64 value')
  }
  let binary: string
  try {
    binary = atob(value)
  } catch {
    throw new Error('invalid MLS base64 value')
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0))
  if (
    bytes.length < minimum
    || bytes.length > maximum
    || encodeBase64(bytes) !== value
  ) {
    throw new Error('MLS base64 value is not canonical or is outside bounds')
  }
  return bytes
}

function encodeBase64(bytes: Uint8Array): string {
  let binary = ''
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000))
  }
  return btoa(binary)
}

function equalBytes(left: number[], right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index])
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    value,
  )
}

function requireSafePositiveInteger(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`MLS ${field} must be a positive safe integer`)
  }
}

function requireCanonicalAddress(address: AccountAddress | undefined): AccountAddress {
  if (!address?.server) throw new Error('MLS operation requires a federated account address')
  const canonical = canonicalAccountAddress(address)
  if (parseAccountAddress(canonical)?.server !== address.server) {
    throw new Error('MLS account address is not canonical')
  }
  return address
}

function compareMembers(left: MlsConversationMember, right: MlsConversationMember): number {
  return canonicalAccountAddress(left.address).localeCompare(
    canonicalAccountAddress(right.address),
  )
}

function encodeHex(bytes: number[]): string {
  return bytes.map((byte) => {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error('invalid MLS byte array')
    }
    return byte.toString(16).padStart(2, '0')
  }).join('')
}

function bytesToUuid(bytes: number[]): string {
  if (bytes.length !== 16) throw new Error('invalid MLS conversation UUID bytes')
  const hex = encodeHex(bytes)
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

function decodeAnonymousEnvelope(value: string): AnonymousMlsDeviceEnvelope {
  const bytes = decodeCanonicalBase64(value, 2, 1024 * 1024)
  let parsed: unknown
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    throw new Error('anonymous MLS mailbox envelope is not canonical JSON')
  }
  if (
    typeof parsed !== 'object'
    || parsed === null
    || !('deviceId' in parsed)
    || !Number.isSafeInteger(parsed.deviceId)
    || parsed.deviceId !== Number(parsed.deviceId)
    || !('encapsulatedKey' in parsed)
    || typeof parsed.encapsulatedKey !== 'string'
    || !('ciphertext' in parsed)
    || typeof parsed.ciphertext !== 'string'
  ) {
    throw new Error('anonymous MLS mailbox envelope has an invalid shape')
  }
  return parsed as AnonymousMlsDeviceEnvelope
}

function requireAnonymousDeliveryResponse(
  value: unknown,
  expectedDevices: number,
): { accepted: true; storedDevices: number; deduplicated: boolean } {
  if (
    typeof value !== 'object'
    || value === null
    || !('accepted' in value)
    || value.accepted !== true
    || !('storedDevices' in value)
    || value.storedDevices !== expectedDevices
    || !('deduplicated' in value)
    || typeof value.deduplicated !== 'boolean'
  ) {
    throw new Error('server returned an invalid anonymous MLS delivery acknowledgement')
  }
  return value as { accepted: true; storedDevices: number; deduplicated: boolean }
}
