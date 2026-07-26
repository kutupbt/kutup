import type {
  AccountAddress,
  ChatTransportPort,
  FinalizedMlsMembershipChange,
  LocalMlsConversationRecord,
  LocalMlsGroupState,
  MlsConversationMember,
  MlsMailboxEnvelope,
  MlsWelcomeInspection,
  PendingMlsMembershipChange,
  PendingMlsInvitation,
  PreparedMlsGroupGenesis,
  VerifiedMlsCredential,
  WasmChatClientHandle,
} from './types'

const MLS_PROTOCOL_VERSION = 1
const DEFAULT_KEY_PACKAGE_TARGET = 20
const KEY_PACKAGE_LIFETIME_SECONDS = 30 * 24 * 60 * 60
const MAX_MAILBOX_PAGES = 64

type CryptoLock = <T>(operation: () => Promise<T>) => Promise<T>

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
  constructor(
    private readonly client: WasmChatClientHandle,
    private readonly transport: ChatTransportPort,
    private readonly withCryptoLock: CryptoLock,
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
    return { group: prepared.group, conversation: published }
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
   * Atomically stage one add-only or remove-only MLS membership transition,
   * then replay its exact destination deliveries and quorum request. All
   * signature and quorum decisions remain inside the shared Rust engine.
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
    return this.publishPendingMembershipChange(prepared.control)
  }

  /** Replay exact staged deliveries and the exact signed block after restart. */
  async reconcilePendingMembershipChanges(): Promise<FinalizedMlsMembershipChange[]> {
    const pending = await this.withCryptoLock(() =>
      this.client.pendingMlsMembershipChanges(),
    )
    const finalized: FinalizedMlsMembershipChange[] = []
    for (const control of pending) {
      validatePendingMembershipChange(control, Uint8Array.from(control.mlsGroupId))
      finalized.push(await this.publishPendingMembershipChange(control))
    }
    return finalized
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
      await this.transport.mlsKeyPackageCount(this.client.deviceId),
      this.client.deviceId,
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
        deviceId: this.client.deviceId,
        keyPackages: packages,
      }),
      this.client.deviceId,
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

  async invitations(): Promise<PendingMlsInvitation[]> {
    const now = Math.floor(Date.now() / 1000)
    const invitations = await this.transport.listMlsInvitations()
    for (const invitation of invitations) validateInvitation(invitation, now)
    return invitations
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
    let resumed = false
    let group = await this.withCryptoLock(() => this.client.mlsGroupState(groupId))
    if (group) {
      resumed = true
      if (group.epoch !== verified.invitedEpoch) {
        throw new Error('durable MLS group epoch differs from the pending invitation')
      }
    } else {
      group = await this.withCryptoLock(() =>
        this.client.joinMlsFromWelcome(groupId, welcome, verified.expectedMembers),
      ) as LocalMlsGroupState
      if (group.epoch !== verified.invitedEpoch) {
        throw new Error('MLS Welcome epoch differs from authenticated invitation history')
      }
    }
    const decision = await this.transport.respondMlsInvitation({
      conversationId: verified.conversationId,
      incarnation: verified.incarnation,
      accept: true,
    })
    if (decision.status !== 'active') {
      throw new Error('server did not activate the verified MLS invitation')
    }
    await this.transport.ackMlsMailbox(
      this.client.deviceId,
      envelopes.map((envelope) => envelope.id),
    )
    return { group, serverAccepted: true, resumed }
  }

  private async membershipEnvelopes(
    conversationId: string,
    incarnation: number,
  ): Promise<MlsMailboxEnvelope[]> {
    let after: string | undefined
    const matching: MlsMailboxEnvelope[] = []
    for (let pageIndex = 0; pageIndex < MAX_MAILBOX_PAGES; pageIndex += 1) {
      const page = await this.transport.drainMlsMailbox(this.client.deviceId, after, 256)
      for (const envelope of page.envelopes) {
        validateMailboxEnvelope(envelope)
        if (
          envelope.deliveryKind === 'membership_control'
          && envelope.conversationId === conversationId
          && envelope.incarnation === incarnation
        ) {
          matching.push(envelope)
        }
      }
      if (!page.nextCursor || page.nextCursor === after || page.envelopes.length < 256) {
        return matching
      }
      after = page.nextCursor
    }
    throw new Error('MLS mailbox exceeded the bounded invitation scan')
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
  if (
    !genesis
    || !isUuid(genesis.conversationId)
    || genesis.protocolVersion !== MLS_PROTOCOL_VERSION
    || genesis.incarnation !== 1
    || genesis.kind !== 'group'
    || genesis.initialEpoch !== 0
    || genesis.memberCount !== 1
    || record.request.members.length !== 1
    || !Number.isSafeInteger(record.lastFinalizedHeight)
    || record.lastFinalizedHeight < 0
    || !Number.isSafeInteger(record.lastFinalizedEpoch)
    || record.lastFinalizedEpoch < 0
    || record.currentRoster.length < 1
    || record.currentRoster.length > 1000
    || record.currentAuthoritySet.authorities.length < 1
    || record.currentOwnerSet.owners.length < 1
    || (
      record.lastFinalizedHeight === 0
      && (record.lastFinalizedEpoch !== 0 || record.lastBlockHash !== undefined)
    )
    || (
      record.lastFinalizedHeight > 0
      && !isSha256(record.lastBlockHash)
    )
    || (record.status !== 'pending_genesis' && record.status !== 'active')
    || (record.status === 'pending_genesis' && record.serverGenesisHash !== undefined)
    || (
      record.status === 'active'
      && !isSha256(record.serverGenesisHash)
    )
  ) {
    throw new Error('invalid durable MLS group genesis record')
  }
  decodeCanonicalBase64(genesis.mlsGroupId, 16, 255)
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

function requireControlBlockResponse(
  value: unknown,
  control: PendingMlsMembershipChange,
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
