import type {
  AccountAddress,
  AnonymousMlsDeviceEnvelope,
  AppliedInboundMlsCommit,
  AppliedInboundMlsApplication,
  ChatTransportPort,
  DerivedMlsDeliveryCapability,
  FinalizedMlsMembershipChange,
  LocalMlsConversationRecord,
  LocalMlsGroupState,
  MlsConversationMember,
  MlsMailboxEnvelope,
  MlsOutboxEntry,
  MlsWelcomeInspection,
  PendingMlsMembershipChange,
  PendingMlsInvitation,
  PreparedMlsGroupGenesis,
  VerifiedMlsCredential,
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
    await this.reconcileInboundMembershipCommits()
    await this.reconcilePendingApplicationMessages()
    await this.reconcileInboundApplicationMessages()
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
    await this.transport.ackMlsMailbox(
      this.deviceId,
      envelopes.map((envelope) => envelope.id),
    )
    return { group, serverAccepted: true, resumed }
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
    await this.transport.publishMlsDeliveryCapability({
      protocolVersion: MLS_PROTOCOL_VERSION,
      conversationId: conversation.request.genesis.conversationId,
      incarnation: conversation.request.genesis.incarnation,
      epoch: derived.epoch,
      capabilityKind: 'group',
      capabilityHash: encodeHex(derived.verifierHash),
      policySequence: 1,
    })
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
