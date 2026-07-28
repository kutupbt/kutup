import { afterEach, describe, expect, it, vi } from 'vitest'
import { MlsConversationService } from './mls-service'
import type {
  ChatTransportPort,
  LocalMlsConversationRecord,
  LocalMlsGroupState,
  MlsInvitationFeedback,
  PendingMlsOwnerApprovalRequest,
  PendingMlsInvitation,
  WasmChatClientHandle,
} from './types'

const conversationId = '11111111-1111-4111-8111-111111111111'
const envelopeId = '22222222-2222-4222-8222-222222222222'
const sendId = '33333333-3333-4333-8333-333333333333'
const groupId = btoa(String.fromCharCode(...new Uint8Array(16).fill(7)))
const welcome = btoa(String.fromCharCode(...new Uint8Array(32).fill(9)))
const genesisGroupBytes = new Uint8Array(32).fill(5)
const genesisGroupId = btoa(String.fromCharCode(...genesisGroupBytes))
const genesisHash = 'ab'.repeat(32)
const proposalId = '44444444-4444-4444-8444-444444444444'
const controlBlockHash = 'ef'.repeat(32)
const recoveryGroupBytes = new Uint8Array(32).fill(6)
const recoveryGroupId = btoa(String.fromCharCode(...recoveryGroupBytes))
const recoveryDigest = 'bd'.repeat(32)

function pendingGenesis(): LocalMlsConversationRecord {
  return {
    request: {
      genesis: {
        protocolVersion: 1,
        conversationId,
        incarnation: 1,
        mlsGroupId: genesisGroupId,
        kind: 'group',
        suite: 2,
        rosterCommitment: 'cd'.repeat(32),
        memberCount: 1,
        authoritySet: {
          sequence: 1,
          authorities: [
            {
              domain: 'alpha.example',
              keyId: '11'.repeat(32),
              publicKey: btoa(String.fromCharCode(...new Uint8Array(32).fill(1))),
            },
          ],
          requiredQuorum: 1,
        },
        ownerSet: {
          sequence: 1,
          owners: [
            {
              ownerId: '22'.repeat(32),
              publicKey: btoa(String.fromCharCode(...new Uint8Array(32).fill(2))),
            },
          ],
          requiredQuorum: 1,
        },
        initialEpoch: 0,
        createdAt: 1_700_000_000,
      },
      members: [
        {
          address: { username: 'alice', server: 'alpha.example' },
          isAdmin: true,
          ownerId: '22'.repeat(32),
        },
      ],
    },
    status: 'pending_genesis',
    lastFinalizedHeight: 0,
    lastFinalizedEpoch: 0,
    currentRoster: [
      {
        address: { username: 'alice', server: 'alpha.example' },
        isAdmin: true,
        ownerId: '22'.repeat(32),
      },
    ],
    currentAuthoritySet: {
      sequence: 1,
      authorities: [
        {
          domain: 'alpha.example',
          keyId: '11'.repeat(32),
          publicKey: btoa(String.fromCharCode(...new Uint8Array(32).fill(1))),
        },
      ],
      requiredQuorum: 1,
    },
    currentOwnerSet: {
      sequence: 1,
      owners: [
        {
          ownerId: '22'.repeat(32),
          publicKey: btoa(String.fromCharCode(...new Uint8Array(32).fill(2))),
        },
      ],
      requiredQuorum: 1,
    },
    genesisAuthorizationPolicy: {
      policyVersion: 1,
      sequence: 1,
      applicationSenders: 1,
    },
    genesisCryptographicPolicy: {
      policyVersion: 1,
      sequence: 1,
      suite: 2,
      requiredPrivateControlExtension: 0xff4b,
      maximumPastEpochs: 2,
      anonymousDeliveryRequired: true,
      paddingBlockBytes: 1024,
      maximumApplicationPlaintextBytes: 1024 * 1024,
    },
    currentAuthorizationPolicy: {
      policyVersion: 1,
      sequence: 1,
      applicationSenders: 1,
    },
    currentCryptographicPolicy: {
      policyVersion: 1,
      sequence: 1,
      suite: 2,
      requiredPrivateControlExtension: 0xff4b,
      maximumPastEpochs: 2,
      anonymousDeliveryRequired: true,
      paddingBlockBytes: 1024,
      maximumApplicationPlaintextBytes: 1024 * 1024,
    },
  }
}

function activeGenesis(): LocalMlsConversationRecord {
  return {
    ...pendingGenesis(),
    status: 'active',
    serverGenesisHash: genesisHash,
  }
}

function invitation(): PendingMlsInvitation {
  return {
    conversationId,
    incarnation: 1,
    mlsGroupId: groupId,
    invitedEpoch: 1,
    expiresAt: Math.floor(Date.now() / 1000) + 3600,
  }
}

function invitationFeedback(): MlsInvitationFeedback {
  return {
    protocolVersion: 1,
    conversationId,
    incarnation: 1,
    member: { username: 'bobby', server: 'beta.example' },
    invitedEpoch: 1,
    decision: 'rejected',
    decidedAt: 1_700_000_100,
  }
}

function pendingMembership() {
  return {
    mlsGroupId: [...genesisGroupBytes],
    nextRoster: [
      {
        address: { username: 'alice', server: 'alpha.example' },
        isAdmin: true,
        ownerId: '22'.repeat(32),
      },
      {
        address: { username: 'bobby', server: 'beta.example' },
        isAdmin: false,
      },
    ],
    deliveries: [
      { destination: 'alpha.example', deliveryDigest: '31'.repeat(32) },
      { destination: 'beta.example', deliveryDigest: '32'.repeat(32) },
    ],
    transition: {
      conversationId,
      incarnation: 1,
      proposalId,
    },
    voteRequest: {
      block: {
        conversationId,
        incarnation: 1,
        height: 1,
        epochBefore: 0,
        epochAfter: 1,
      },
    },
    commitHash: 'cd'.repeat(32),
  }
}

function finalizedMembership() {
  const conversation = {
    ...activeGenesis(),
    lastFinalizedHeight: 1,
    lastFinalizedEpoch: 1,
    lastBlockHash: controlBlockHash,
    currentRoster: pendingMembership().nextRoster,
  }
  return {
    group: { mlsGroupId: [...genesisGroupBytes], epoch: 1 },
    conversation,
  }
}

function pendingAuthority() {
  return {
    mlsGroupId: [...genesisGroupBytes],
    deliveries: [{ destination: 'alpha.example', deliveryDigest: '41'.repeat(32) }],
    authorityChange: {
      nextAuthoritySet: {
        sequence: 2,
        authorities: [
          activeGenesis().currentAuthoritySet.authorities[0],
          {
            domain: 'beta.example',
            keyId: '33'.repeat(32),
            publicKey: btoa(String.fromCharCode(...new Uint8Array(32).fill(3))),
          },
        ],
        requiredQuorum: 2,
      },
      deliveryTransition: {
        conversationId,
        incarnation: 1,
        proposalId,
      },
    },
    voteRequest: {
      block: {
        conversationId,
        incarnation: 1,
        height: 1,
        epochBefore: 0,
        epochAfter: 1,
      },
    },
    commitHash: 'dc'.repeat(32),
  }
}

function finalizedAuthority() {
  return {
    group: { mlsGroupId: [...genesisGroupBytes], epoch: 1 },
    conversation: {
      ...activeGenesis(),
      lastFinalizedHeight: 1,
      lastFinalizedEpoch: 1,
      lastBlockHash: controlBlockHash,
      currentAuthoritySet: pendingAuthority().authorityChange.nextAuthoritySet,
    },
  }
}

function pendingOwner() {
  return {
    mlsGroupId: [...genesisGroupBytes],
    nextRoster: activeGenesis().currentRoster,
    deliveries: [{ destination: 'alpha.example', deliveryDigest: '51'.repeat(32) }],
    ownerChange: {
      nextOwnerSet: {
        sequence: 2,
        owners: activeGenesis().currentOwnerSet.owners,
        requiredQuorum: 1,
      },
      deliveryTransition: {
        conversationId,
        incarnation: 1,
        proposalId,
      },
    },
    voteRequest: {
      block: {
        conversationId,
        incarnation: 1,
        height: 1,
        epochBefore: 0,
        epochAfter: 1,
      },
    },
    commitHash: 'ed'.repeat(32),
  }
}

function finalizedOwner() {
  return {
    group: { mlsGroupId: [...genesisGroupBytes], epoch: 1 },
    conversation: {
      ...activeGenesis(),
      lastFinalizedHeight: 1,
      lastFinalizedEpoch: 1,
      lastBlockHash: controlBlockHash,
      currentOwnerSet: pendingOwner().ownerChange.nextOwnerSet,
    },
  }
}

function pendingClose() {
  return {
    mlsGroupId: [...genesisGroupBytes],
    currentRoster: activeGenesis().currentRoster,
    deliveries: [{ destination: 'alpha.example', deliveryDigest: '61'.repeat(32) }],
    transition: {
      conversationId,
      incarnation: 1,
      proposalId,
    },
    voteRequest: {
      block: {
        conversationId,
        incarnation: 1,
        height: 1,
        epochBefore: 0,
        epochAfter: 1,
      },
    },
    commitHash: 'fa'.repeat(32),
  }
}

function finalizedClose() {
  return {
    group: { mlsGroupId: [...genesisGroupBytes], epoch: 1 },
    conversation: {
      ...activeGenesis(),
      status: 'closed' as const,
      lastFinalizedHeight: 1,
      lastFinalizedEpoch: 1,
      lastBlockHash: controlBlockHash,
    },
  }
}

function pendingPolicy() {
  return {
    mlsGroupId: [...genesisGroupBytes],
    nextAuthorizationPolicy: {
      policyVersion: 1 as const,
      sequence: 2,
      applicationSenders: 2 as const,
    },
    currentRoster: activeGenesis().currentRoster,
    deliveries: [{ destination: 'alpha.example', deliveryDigest: '71'.repeat(32) }],
    transition: {
      conversationId,
      incarnation: 1,
      proposalId,
    },
    voteRequest: {
      block: {
        conversationId,
        incarnation: 1,
        height: 1,
        epochBefore: 0,
        epochAfter: 1,
      },
    },
    commitHash: 'fb'.repeat(32),
  }
}

function finalizedPolicy() {
  return {
    group: { mlsGroupId: [...genesisGroupBytes], epoch: 1 },
    conversation: {
      ...activeGenesis(),
      lastFinalizedHeight: 1,
      lastFinalizedEpoch: 1,
      lastBlockHash: controlBlockHash,
      currentAuthorizationPolicy: pendingPolicy().nextAuthorizationPolicy,
    },
  }
}

function recoveryPrevious(): LocalMlsConversationRecord {
  return finalizedMembership().conversation
}

function recoveryStatement() {
  const previous = recoveryPrevious()
  return {
    plan: {
      protocolVersion: 1,
      conversationId,
      previousIncarnation: 1,
      proposalId,
      previousGenesisHash: genesisHash,
      previousHeight: 1,
      previousEpoch: 1,
      previousBlockHash: controlBlockHash,
      previousRosterCommitment: 'ce'.repeat(32),
      participantDomains: ['alpha.example', 'beta.example'],
      newGenesis: {
        ...previous.request.genesis,
        incarnation: 2,
        mlsGroupId: recoveryGroupId,
        rosterCommitment: 'ce'.repeat(32),
        memberCount: 2,
        initialEpoch: 1,
      },
      deliveries: [
        { destination: 'alpha.example', deliveryDigest: '71'.repeat(32) },
        { destination: 'beta.example', deliveryDigest: '72'.repeat(32) },
      ],
    },
    proposal: { signed: 'owner-proposal' },
    ownerApproval: { approvals: ['owner'] },
  }
}

function pendingRecovery() {
  return {
    mlsGroupId: [...genesisGroupBytes],
    newMlsGroupId: [...recoveryGroupBytes],
    request: {
      recovery: recoveryStatement(),
      creator: { username: 'alice', server: 'alpha.example' },
      creatorDeviceId: 7,
      members: recoveryPrevious().currentRoster,
      deliveries: [
        { destination: 'alpha.example', envelopes: [] },
        { destination: 'beta.example', envelopes: [{ deviceId: 7 }] },
      ],
    },
    commitHash: 'ca'.repeat(32),
  }
}

function finalizedRecovery() {
  const previous = recoveryPrevious()
  const conversation: LocalMlsConversationRecord = {
    request: {
      genesis: recoveryStatement().plan.newGenesis,
      members: previous.currentRoster,
    },
    status: 'active',
    serverGenesisHash: 'bc'.repeat(32),
    recoveryDigest,
    lastFinalizedHeight: 0,
    lastFinalizedEpoch: 1,
    currentRoster: previous.currentRoster,
    currentAuthoritySet: previous.currentAuthoritySet,
    currentOwnerSet: previous.currentOwnerSet,
    genesisAuthorizationPolicy: previous.currentAuthorizationPolicy,
    genesisCryptographicPolicy: previous.currentCryptographicPolicy,
    currentAuthorizationPolicy: previous.currentAuthorizationPolicy,
    currentCryptographicPolicy: previous.currentCryptographicPolicy,
  }
  return {
    group: { mlsGroupId: [...recoveryGroupBytes], epoch: 1 },
    conversation,
    archivedIncarnation: { ...previous, status: 'read_only' as const },
  }
}

function ownerApprovalRequest(): PendingMlsOwnerApprovalRequest {
  return {
    mlsGroupId: [...genesisGroupBytes],
    requester: { username: 'alice', server: 'alpha.example' },
    request: {
      protocolVersion: 1,
      ownerSetSequence: 1,
      proposal: {
        conversationId,
        incarnation: 1,
        proposalId,
        baseEpoch: 0,
        actionType: 3,
      },
      transitionDigest: 'ac'.repeat(32),
      ownerChange: { nextOwnerSet: pendingOwner().ownerChange.nextOwnerSet },
      nextRoster: activeGenesis().currentRoster,
      requestedAt: 1_700_000_000,
      expiresAt: 1_700_086_400,
    },
  }
}

function applicationOutboxEntry() {
  return {
    sendId,
    conversationId: [...genesisGroupBytes.subarray(0, 16)],
    incarnation: 1,
    mlsGroupId: [...genesisGroupBytes],
    epoch: 1,
    contentDigest: [...new Uint8Array(32).fill(6)],
    content: [1, 2, 3],
    ciphertext: [4, 5, 6],
    expectedRecipients: ['bobby@beta.example'],
    deliveries: [],
    createdAt: 1_700_000_000_000,
    attempts: 0,
  }
}

function harness(
  existing: LocalMlsGroupState | null = null,
  localRecords: LocalMlsConversationRecord[] = [pendingGenesis()],
  selfAddress = { username: 'bobby', server: 'beta.example' },
) {
  const client = {
    deviceId: 7,
    mlsKeyPackageCount: vi.fn(),
    generateMlsKeyPackage: vi.fn().mockResolvedValue({ keyPackageRef: 'package' }),
    fetchVerifiedMlsOrderingPolicy: vi.fn().mockImplementation(async (domain: string) => ({
      canonicalDomain: domain,
    })),
    prepareMlsGroupGenesis: vi.fn().mockResolvedValue({
      group: { mlsGroupId: [...genesisGroupBytes], epoch: 0 },
      conversation: pendingGenesis(),
    }),
    localMlsConversations: vi.fn().mockResolvedValue(localRecords),
    markMlsGroupGenesisPublished: vi.fn().mockResolvedValue(activeGenesis()),
    prepareMlsMembershipChange: vi.fn().mockResolvedValue({
      pending: {
        mlsGroupId: [...genesisGroupBytes],
        epochBefore: 0,
        epochAfter: 1,
        commitHash: 'cd'.repeat(32),
        commit: [1, 2, 3],
        welcome: [4, 5, 6],
      },
      control: pendingMembership(),
    }),
    mlsGroupDevices: vi.fn().mockResolvedValue([
      {
        address: { username: 'alice', server: 'alpha.example' },
        deviceId: 7,
      },
    ]),
    prepareMlsDeviceSync: vi.fn().mockResolvedValue({
      pending: {
        mlsGroupId: [...genesisGroupBytes],
        epochBefore: 0,
        epochAfter: 1,
        commitHash: 'cd'.repeat(32),
        commit: [1, 2, 3],
        welcome: [4, 5, 6],
      },
      control: pendingMembership(),
    }),
    pendingMlsMembershipChanges: vi.fn().mockResolvedValue([pendingMembership()]),
    buildMlsMembershipCommitRequest: vi.fn().mockResolvedValue({ finalized: 'request' }),
    finalizeMlsMembershipChange: vi.fn().mockResolvedValue(finalizedMembership()),
    prepareMlsAuthorityChange: vi.fn().mockResolvedValue({
      pending: {
        mlsGroupId: [...genesisGroupBytes],
        epochBefore: 0,
        epochAfter: 1,
        commitHash: 'dc'.repeat(32),
        commit: [9, 8, 7],
      },
      control: pendingAuthority(),
    }),
    pendingMlsAuthorityChanges: vi.fn().mockResolvedValue([pendingAuthority()]),
    recordMlsAuthorityPreviousQuorum: vi.fn().mockResolvedValue({ next: 'vote-request' }),
    buildMlsAuthorityCommitRequest: vi.fn().mockResolvedValue({ finalized: 'authority-request' }),
    finalizeMlsAuthorityChange: vi.fn().mockResolvedValue(finalizedAuthority()),
    ensureMlsOwnerCandidate: vi.fn().mockResolvedValue({
      protocolVersion: 1,
      conversationId,
      incarnation: 1,
      account: { username: 'bobby', server: 'beta.example' },
      ownerId: '44'.repeat(32),
      publicKey: btoa(String.fromCharCode(...new Uint8Array(32).fill(4))),
      createdAt: 1_700_000_000,
      signature: btoa(String.fromCharCode(...new Uint8Array(64).fill(5))),
    }),
    mlsOwnerCandidates: vi.fn().mockResolvedValue([]),
    createMlsOwnerCandidateMessage: vi.fn().mockResolvedValue(null),
    prepareMlsOwnerChange: vi.fn().mockResolvedValue({
      pending: {
        mlsGroupId: [...genesisGroupBytes],
        epochBefore: 0,
        epochAfter: 1,
        commitHash: 'ed'.repeat(32),
        commit: [6, 7, 8],
      },
      control: pendingOwner(),
    }),
    pendingMlsOwnerChanges: vi.fn().mockResolvedValue([pendingOwner()]),
    mlsOwnerChangeHasQuorum: vi.fn().mockResolvedValue(true),
    createMlsOwnerApprovalRequestMessage: vi.fn().mockResolvedValue(null),
    pendingMlsOwnerApprovalRequests: vi.fn().mockResolvedValue([]),
    approveMlsOwnerApprovalRequest: vi.fn().mockResolvedValue(null),
    rejectMlsOwnerApprovalRequest: vi.fn().mockResolvedValue(undefined),
    buildMlsOwnerCommitRequest: vi.fn().mockResolvedValue({ finalized: 'owner-request' }),
    finalizeMlsOwnerChange: vi.fn().mockResolvedValue(finalizedOwner()),
    prepareMlsClose: vi.fn().mockResolvedValue({
      pending: {
        mlsGroupId: [...genesisGroupBytes],
        epochBefore: 0,
        epochAfter: 1,
        commitHash: 'fa'.repeat(32),
        commit: [10, 11, 12],
      },
      control: pendingClose(),
    }),
    pendingMlsCloses: vi.fn().mockResolvedValue([pendingClose()]),
    mlsCloseHasOwnerQuorum: vi.fn().mockResolvedValue(true),
    buildMlsCloseCommitRequest: vi.fn().mockResolvedValue({ finalized: 'close-request' }),
    finalizeMlsClose: vi.fn().mockResolvedValue(finalizedClose()),
    prepareMlsAuthorizationPolicyChange: vi.fn().mockResolvedValue({
      pending: {
        mlsGroupId: [...genesisGroupBytes],
        epochBefore: 0,
        epochAfter: 1,
        commitHash: 'fb'.repeat(32),
        commit: [13, 14, 15],
      },
      control: pendingPolicy(),
    }),
    prepareMlsCryptographicPolicyChange: vi.fn(),
    pendingMlsPolicyChanges: vi.fn().mockResolvedValue([pendingPolicy()]),
    mlsPolicyChangeHasOwnerQuorum: vi.fn().mockResolvedValue(true),
    buildMlsPolicyCommitRequest: vi.fn().mockResolvedValue({ finalized: 'policy-request' }),
    finalizeMlsPolicyChange: vi.fn().mockResolvedValue(finalizedPolicy()),
    fetchVerifiedIdentifiedMlsKeyPackages: vi.fn().mockImplementation(
      async (recipient: { username: string; server: string }) => [{
        wire: { deviceId: 7 },
        credential: {
          credentialIdentity: `${recipient.username}@${recipient.server}#7`,
          credentialPublicKey: [...new Uint8Array(65).fill(4)],
        },
        anonymousDeliveryPublicKey: [...new Uint8Array(65).fill(5)],
      }],
    ),
    prepareMlsGroupRecovery: vi.fn().mockResolvedValue({
      pending: {
        mlsGroupId: [...recoveryGroupBytes],
        epochBefore: 0,
        epochAfter: 1,
        commitHash: 'ca'.repeat(32),
        commit: [1, 3, 5],
        welcome: [2, 4, 6],
      },
      control: pendingRecovery(),
    }),
    pendingMlsRecoveries: vi.fn().mockResolvedValue([]),
    localMlsIncarnationHistory: vi.fn().mockResolvedValue([]),
    mlsRecoveryHasOwnerQuorum: vi.fn().mockResolvedValue(true),
    finalizeMlsGroupRecovery: vi.fn().mockResolvedValue(finalizedRecovery()),
    mlsGroupState: vi.fn().mockResolvedValue(existing),
    inspectMlsWelcome: vi.fn().mockResolvedValue({
      mlsGroupId: [...new Uint8Array(16).fill(7)],
      epoch: 1,
      privateControlState: {
        protocolVersion: 1,
        conversationId,
        incarnation: 1,
        height: 1,
        epoch: 1,
      },
      claimedMembers: [
        {
          credentialIdentity: 'alice@example.test#7',
          credentialPublicKey: [...new Uint8Array(65).fill(4)],
        },
      ],
    }),
    resolveMlsWelcomeClaims: vi.fn().mockResolvedValue([
      {
        credentialIdentity: 'alice@example.test#7',
        credentialPublicKey: [...new Uint8Array(65).fill(4)],
      },
    ]),
    resolveMlsSenderClaim: vi.fn().mockResolvedValue({
      credentialIdentity: 'alice@example.test#7',
      credentialPublicKey: [...new Uint8Array(65).fill(4)],
    }),
    processedMlsControlEnvelope: vi.fn().mockResolvedValue(null),
    inspectInboundMlsCommit: vi.fn().mockResolvedValue({
      mlsGroupId: [...genesisGroupBytes],
      epochBefore: 0,
      epochAfter: 1,
      commitHash: 'cd'.repeat(32),
      claimedMembers: [
        {
          credentialIdentity: 'alice@example.test#7',
          credentialPublicKey: [...new Uint8Array(65).fill(4)],
        },
      ],
      privateControlState: {
        protocolVersion: 1,
        conversationId,
        incarnation: 1,
        height: 1,
        epoch: 1,
      },
    }),
    applyOrderedInboundMlsMembershipCommit: vi.fn().mockResolvedValue({
      ...finalizedMembership(),
      receipt: {
        envelopeId,
        cursor: '1',
        sendId,
        conversationId,
        incarnation: 1,
        height: 1,
        epoch: 1,
        blockHash: controlBlockHash,
      },
      idempotent: false,
    }),
    fetchVerifiedMlsKeyPackages: vi.fn().mockResolvedValue([
      { wire: { deviceId: 7 }, credential: { credentialIdentity: 'bob@example.test#7' } },
    ]),
    createMlsTextMessage: vi.fn().mockResolvedValue({
      sendId,
      conversationId: [...genesisGroupBytes.subarray(0, 16)],
      incarnation: 1,
      mlsGroupId: [...genesisGroupBytes],
      epoch: 1,
      contentDigest: [...new Uint8Array(32).fill(6)],
      content: [1, 2, 3],
      ciphertext: [4, 5, 6],
      expectedRecipients: ['bobby@beta.example'],
      deliveries: [],
      createdAt: 1_700_000_000_000,
      attempts: 0,
    }),
    deriveMlsDeliveryCapability: vi.fn().mockResolvedValue({
      epoch: 1,
      capability: [...new Uint8Array(16).fill(8)],
      verifierHash: [...new Uint8Array(32).fill(9)],
    }),
    stageMlsApplicationDelivery: vi.fn().mockImplementation(async (
      _sendId: string,
      recipient: { username: string; server: string },
    ) => ({
      entry: {
        sendId,
        conversationId: [...genesisGroupBytes.subarray(0, 16)],
        incarnation: 1,
        mlsGroupId: [...genesisGroupBytes],
        epoch: 1,
        contentDigest: [...new Uint8Array(32).fill(6)],
        content: [1, 2, 3],
        ciphertext: [4, 5, 6],
        expectedRecipients: ['bobby@beta.example'],
        deliveries: [{
          recipient: `${recipient.username}@${recipient.server}`,
          submission: [7, 8, 9],
          attempts: 0,
          delivered: false,
        }],
        createdAt: 1_700_000_000_000,
        attempts: 0,
      },
    })),
    noteMlsApplicationDeliveryAttempt: vi.fn().mockResolvedValue({
      envelopes: [{ deviceId: 7 }],
    }),
    markMlsApplicationRecipientDelivered: vi.fn().mockResolvedValue(undefined),
    pendingMlsApplicationMessages: vi.fn().mockResolvedValue([]),
    inspectAnonymousMlsApplicationEnvelope: vi.fn().mockResolvedValue({
      mlsGroupId: [...genesisGroupBytes],
      conversationId,
      incarnation: 1,
      epoch: 1,
      claimedSender: {
        credentialIdentity: 'alice@example.test#7',
        credentialPublicKey: [...new Uint8Array(65).fill(4)],
      },
    }),
    processedMlsApplicationEnvelope: vi.fn().mockResolvedValue(null),
    applyAnonymousMlsApplicationEnvelope: vi.fn().mockResolvedValue({
      message: {
        recordId: `in:${envelopeId}`,
        messageId: sendId,
        conversationId: [...genesisGroupBytes.subarray(0, 16)],
        incarnation: 1,
        mlsGroupId: [...genesisGroupBytes],
        epoch: 1,
        sender: 'alice@example.test',
        senderDeviceId: 7,
        outgoing: false,
        cursor: 1,
        transportDigest: [...new Uint8Array(32).fill(6)],
        content: [1, 2, 3],
        timestampMs: 1_700_000_000_000,
        delivered: true,
        deduplicated: false,
      },
      idempotent: false,
    }),
    joinMlsFromWelcomeWithControlHistory: vi.fn().mockResolvedValue({
      group: {
        mlsGroupId: [...new Uint8Array(16).fill(7)],
        epoch: 1,
      },
      conversation: finalizedMembership().conversation,
    }),
    joinMlsFromRecoveryWelcome: vi.fn().mockResolvedValue({
      group: finalizedRecovery().group,
      conversation: finalizedRecovery().conversation,
    }),
  } as unknown as WasmChatClientHandle
  const transport = {
    mlsKeyPackageCount: vi.fn().mockResolvedValue({ deviceId: 7, available: 18 }),
    publishMlsKeyPackages: vi.fn().mockResolvedValue({ deviceId: 7, available: 20 }),
    createMlsConversation: vi.fn().mockResolvedValue({
      conversationId,
      incarnation: 1,
      genesisHash,
      idempotent: false,
    }),
    recoverMlsConversation: vi.fn().mockResolvedValue({
      conversationId,
      previousIncarnation: 1,
      incarnation: 2,
      recoveryDigest,
      status: 'active',
    }),
    fetchMlsRecovery: vi.fn().mockResolvedValue(recoveryStatement()),
    stageMlsMembershipDelivery: vi.fn().mockResolvedValue({}),
    collectMlsOrderingVotes: vi.fn().mockResolvedValue({ votes: ['authority'] }),
    commitMlsControlBlock: vi.fn().mockResolvedValue({
      conversationId,
      incarnation: 1,
      height: 1,
      epoch: 1,
      blockHash: controlBlockHash,
      idempotent: false,
    }),
    fetchMlsControlHistory: vi.fn().mockResolvedValue({
      bytes: new Uint8Array([123, 125]),
      entryCount: 1,
      nextHeight: '1',
      genesisGroupId,
    }),
    listMlsInvitations: vi.fn().mockResolvedValue([invitation()]),
    listMlsInvitationFeedback: vi.fn().mockResolvedValue([invitationFeedback()]),
    respondMlsInvitation: vi.fn().mockResolvedValue({
      conversationId,
      incarnation: 1,
      status: 'active',
      idempotent: false,
    }),
    drainMlsMailbox: vi.fn().mockResolvedValue({
      envelopes: [
        {
          id: envelopeId,
          cursor: '1',
          deliveryKind: 'membership_control',
          conversationId,
          incarnation: 1,
          sendId,
          opaqueEnvelope: welcome,
          serverTimestamp: Math.floor(Date.now() / 1000),
        },
      ],
      nextCursor: '1',
    }),
    ackMlsMailbox: vi.fn().mockResolvedValue(undefined),
    publishMlsDeliveryCapability: vi.fn().mockResolvedValue(undefined),
    fetchAnonymousMlsKeyPackages: vi.fn(),
    submitAnonymousMlsMessage: vi.fn().mockResolvedValue({
      accepted: true,
      storedDevices: 1,
      deduplicated: false,
    }),
  } as unknown as ChatTransportPort
  const lockCalls = vi.fn()
  const lock = async <T>(operation: () => Promise<T>): Promise<T> => {
    lockCalls()
    return await operation()
  }
  return {
    client,
    transport,
    service: new MlsConversationService(
      client,
      transport,
      lock,
      client.deviceId,
      selfAddress,
    ),
    lock: lockCalls,
  }
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('MlsConversationService', () => {
  it('creates from independently verified authority policies and activates exact genesis', async () => {
    vi.stubGlobal('crypto', {
      randomUUID: () => conversationId,
      getRandomValues: (value: Uint8Array) => {
        value.set(genesisGroupBytes)
        return value
      },
    })
    const { client, transport, service } = harness()
    await expect(
      service.createGroup(
        { username: 'alice', server: 'alpha.example' },
        ['beta.example', 'alpha.example'],
      ),
    ).resolves.toEqual({
      group: { mlsGroupId: [...genesisGroupBytes], epoch: 0 },
      conversation: activeGenesis(),
    })
    expect(client.fetchVerifiedMlsOrderingPolicy).toHaveBeenNthCalledWith(
      1,
      'alpha.example',
    )
    expect(client.fetchVerifiedMlsOrderingPolicy).toHaveBeenNthCalledWith(
      2,
      'beta.example',
    )
    expect(client.prepareMlsGroupGenesis).toHaveBeenCalledWith(
      conversationId,
      genesisGroupBytes,
      { username: 'alice', server: 'alpha.example' },
      [
        { canonicalDomain: 'alpha.example' },
        { canonicalDomain: 'beta.example' },
      ],
      expect.stringMatching(/^[0-9]+$/),
    )
    expect(transport.createMlsConversation).toHaveBeenCalledWith(
      pendingGenesis().request,
    )
    expect(client.markMlsGroupGenesisPublished).toHaveBeenCalledWith(
      conversationId,
      genesisHash,
    )
  })

  it('retains and replays the exact pending genesis after a network failure', async () => {
    const { client, transport, service } = harness()
    vi.mocked(transport.createMlsConversation)
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce({
        conversationId,
        incarnation: 1,
        genesisHash,
        idempotent: true,
      })
    await expect(service.reconcilePendingGroupGeneses()).rejects.toThrow('offline')
    expect(client.markMlsGroupGenesisPublished).not.toHaveBeenCalled()
    await expect(service.reconcilePendingGroupGeneses()).resolves.toEqual([
      activeGenesis(),
    ])
    expect(transport.createMlsConversation).toHaveBeenCalledTimes(2)
    expect(transport.createMlsConversation).toHaveBeenNthCalledWith(
      1,
      pendingGenesis().request,
    )
    expect(transport.createMlsConversation).toHaveBeenNthCalledWith(
      2,
      pendingGenesis().request,
    )
  })

  it('does not activate a genesis when the server acknowledgement is malformed', async () => {
    const { client, transport, service } = harness()
    vi.mocked(transport.createMlsConversation).mockResolvedValueOnce({
      conversationId,
      incarnation: 2,
      genesisHash,
      idempotent: false,
    })
    await expect(service.reconcilePendingGroupGeneses()).rejects.toThrow(
      /invalid MLS conversation genesis acknowledgement/,
    )
    expect(client.markMlsGroupGenesisPublished).not.toHaveBeenCalled()
  })

  it('stages, quorum-finalizes, and merges exact membership control material', async () => {
    vi.stubGlobal('crypto', {
      randomUUID: () => proposalId,
      getRandomValues: (value: Uint8Array) => value,
    })
    const { client, transport, service } = harness(null, [activeGenesis()])
    const nextRoster = pendingMembership().nextRoster
    const additions = [{ wire: { deviceId: 7 }, credential: { credentialIdentity: 'bobby@beta.example#7' } }]
    await expect(
      service.changeGroupMembership(conversationId, nextRoster, additions),
    ).resolves.toEqual(finalizedMembership())
    expect(client.prepareMlsMembershipChange).toHaveBeenCalledWith(
      genesisGroupBytes,
      proposalId,
      nextRoster,
      additions,
      expect.stringMatching(/^[0-9]+$/),
    )
    expect(transport.stageMlsMembershipDelivery).toHaveBeenCalledTimes(2)
    expect(transport.collectMlsOrderingVotes).toHaveBeenCalledWith(
      pendingMembership().voteRequest,
    )
    expect(client.buildMlsMembershipCommitRequest).toHaveBeenCalledWith(
      genesisGroupBytes,
      { votes: ['authority'] },
    )
    expect(transport.commitMlsControlBlock).toHaveBeenCalledWith({
      finalized: 'request',
    })
    expect(client.finalizeMlsMembershipChange).toHaveBeenCalledWith(
      genesisGroupBytes,
      expect.objectContaining({ blockHash: controlBlockHash }),
    )
  })

  it('stages an administrator-only roster transition without KeyPackages', async () => {
    vi.stubGlobal('crypto', {
      randomUUID: () => proposalId,
      getRandomValues: (value: Uint8Array) => value,
    })
    const active = {
      ...activeGenesis(),
      currentRoster: pendingMembership().nextRoster,
    }
    const { client, service } = harness(null, [active])
    await expect(service.setAdministrator(
      conversationId,
      { username: 'bobby', server: 'beta.example' },
      true,
    )).resolves.toEqual(finalizedMembership())
    expect(client.prepareMlsMembershipChange).toHaveBeenCalledWith(
      genesisGroupBytes,
      proposalId,
      [
        pendingMembership().nextRoster[0],
        {
          address: { username: 'bobby', server: 'beta.example' },
          isAdmin: true,
        },
      ],
      [],
      expect.stringMatching(/^[0-9]+$/),
    )
  })

  it('rejects a no-op administrator change before staging MLS state', async () => {
    const active = {
      ...activeGenesis(),
      currentRoster: pendingMembership().nextRoster,
    }
    const { client, service } = harness(null, [active])
    await expect(service.setAdministrator(
      conversationId,
      { username: 'bobby', server: 'beta.example' },
      false,
    )).rejects.toThrow(/already in the requested state/)
    expect(client.prepareMlsMembershipChange).not.toHaveBeenCalled()
  })

  it('replays the exact pending membership operation after a network failure', async () => {
    vi.stubGlobal('crypto', {
      randomUUID: () => proposalId,
      getRandomValues: (value: Uint8Array) => value,
    })
    const { client, transport, service } = harness(null, [activeGenesis()])
    vi.mocked(transport.commitMlsControlBlock)
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce({
        conversationId,
        incarnation: 1,
        height: 1,
        epoch: 1,
        blockHash: controlBlockHash,
        idempotent: true,
      })
    await expect(
      service.changeGroupMembership(
        conversationId,
        pendingMembership().nextRoster,
        [{ package: 'verified' }],
      ),
    ).rejects.toThrow('offline')
    expect(client.finalizeMlsMembershipChange).not.toHaveBeenCalled()
    vi.mocked(client.pendingMlsMembershipChanges).mockResolvedValueOnce([
      {
        ...pendingMembership(),
        finalRequest: { finalized: 'request' },
      },
    ])
    await expect(service.reconcilePendingMembershipChanges()).resolves.toEqual([
      finalizedMembership(),
    ])
    expect(client.prepareMlsMembershipChange).toHaveBeenCalledTimes(1)
    expect(transport.collectMlsOrderingVotes).toHaveBeenCalledTimes(1)
    expect(client.buildMlsMembershipCommitRequest).toHaveBeenCalledTimes(1)
    expect(transport.stageMlsMembershipDelivery).toHaveBeenCalledTimes(4)
    expect(transport.commitMlsControlBlock).toHaveBeenCalledTimes(2)
  })

  it('pins old and new authority quorums before committing the owner-approved change', async () => {
    vi.stubGlobal('crypto', {
      randomUUID: () => proposalId,
      getRandomValues: (value: Uint8Array) => value,
    })
    const { client, transport, service } = harness(null, [activeGenesis()])
    await expect(service.setAuthorities(
      conversationId,
      ['beta.example', 'alpha.example'],
    )).resolves.toEqual(finalizedAuthority())
    expect(client.fetchVerifiedMlsOrderingPolicy).toHaveBeenNthCalledWith(1, 'alpha.example')
    expect(client.fetchVerifiedMlsOrderingPolicy).toHaveBeenNthCalledWith(2, 'beta.example')
    expect(client.prepareMlsAuthorityChange).toHaveBeenCalledWith(
      genesisGroupBytes,
      proposalId,
      [{ canonicalDomain: 'alpha.example' }, { canonicalDomain: 'beta.example' }],
      expect.stringMatching(/^[0-9]+$/),
    )
    expect(transport.stageMlsMembershipDelivery).toHaveBeenCalledTimes(1)
    expect(transport.collectMlsOrderingVotes).toHaveBeenNthCalledWith(
      1,
      pendingAuthority().voteRequest,
    )
    expect(client.recordMlsAuthorityPreviousQuorum).toHaveBeenCalledWith(
      genesisGroupBytes,
      { votes: ['authority'] },
    )
    expect(transport.collectMlsOrderingVotes).toHaveBeenNthCalledWith(
      2,
      { next: 'vote-request' },
    )
    expect(client.buildMlsAuthorityCommitRequest).toHaveBeenCalledWith(
      genesisGroupBytes,
      { votes: ['authority'] },
    )
    expect(client.finalizeMlsAuthorityChange).toHaveBeenCalledWith(
      genesisGroupBytes,
      expect.objectContaining({ blockHash: controlBlockHash }),
    )
  })

  it('resumes an authority change from the exact durable next-set vote request', async () => {
    const { client, transport, service } = harness(null, [activeGenesis()])
    const pending = {
      ...pendingAuthority(),
      previousSetCertificate: { votes: ['old'] },
      newVoteRequest: { durable: 'next-vote-request' },
    }
    vi.mocked(client.pendingMlsAuthorityChanges).mockResolvedValueOnce([pending])
    await expect(service.reconcilePendingAuthorityChanges()).resolves.toEqual([
      finalizedAuthority(),
    ])
    expect(client.prepareMlsAuthorityChange).not.toHaveBeenCalled()
    expect(client.recordMlsAuthorityPreviousQuorum).not.toHaveBeenCalled()
    expect(transport.collectMlsOrderingVotes).toHaveBeenCalledOnce()
    expect(transport.collectMlsOrderingVotes).toHaveBeenCalledWith(
      pending.newVoteRequest,
    )
  })

  it('keeps an owner transition pending until encrypted manual approvals reach quorum', async () => {
    const { client, transport, service } = harness(null, [activeGenesis()])
    vi.mocked(client.mlsOwnerChangeHasQuorum).mockResolvedValueOnce(false)
    vi.mocked(client.createMlsOwnerApprovalRequestMessage)
      .mockResolvedValueOnce(applicationOutboxEntry())

    await expect(service.reconcilePendingOwnerChanges()).resolves.toEqual([])
    expect(client.createMlsOwnerApprovalRequestMessage).toHaveBeenCalledWith(genesisGroupBytes)
    expect(transport.submitAnonymousMlsMessage).toHaveBeenCalledOnce()
    expect(transport.stageMlsMembershipDelivery).not.toHaveBeenCalled()
    expect(transport.collectMlsOrderingVotes).not.toHaveBeenCalled()

    vi.mocked(client.mlsOwnerChangeHasQuorum).mockResolvedValueOnce(true)
    await expect(service.reconcilePendingOwnerChanges()).resolves.toEqual([finalizedOwner()])
    expect(transport.stageMlsMembershipDelivery).toHaveBeenCalledOnce()
    expect(transport.collectMlsOrderingVotes).toHaveBeenCalledWith(pendingOwner().voteRequest)
    expect(client.buildMlsOwnerCommitRequest).toHaveBeenCalledWith(
      genesisGroupBytes,
      { votes: ['authority'] },
    )
    expect(client.finalizeMlsOwnerChange).toHaveBeenCalledWith(
      genesisGroupBytes,
      expect.objectContaining({ blockHash: controlBlockHash }),
    )
  })

  it('exposes explicit approve and reject actions for encrypted owner requests', async () => {
    const { client, transport, service } = harness(null, [activeGenesis()])
    vi.mocked(client.pendingMlsOwnerApprovalRequests)
      .mockResolvedValueOnce([ownerApprovalRequest()])
    await expect(service.pendingOwnerApprovalRequests()).resolves.toEqual([
      ownerApprovalRequest(),
    ])

    vi.mocked(client.approveMlsOwnerApprovalRequest)
      .mockResolvedValueOnce(applicationOutboxEntry())
    await service.approveOwnerGovernance(conversationId)
    expect(client.approveMlsOwnerApprovalRequest).toHaveBeenCalledWith(
      genesisGroupBytes,
      expect.stringMatching(/^[0-9]+$/),
    )
    expect(transport.submitAnonymousMlsMessage).toHaveBeenCalledOnce()

    await service.rejectOwnerGovernance(conversationId)
    expect(client.rejectMlsOwnerApprovalRequest).toHaveBeenCalledWith(genesisGroupBytes)
  })

  it('keeps close pending for owner approval and finalizes the exact terminal epoch', async () => {
    vi.stubGlobal('crypto', {
      randomUUID: () => proposalId,
      getRandomValues: (value: Uint8Array) => value,
    })
    const { client, transport, service } = harness(null, [activeGenesis()])
    vi.mocked(client.mlsCloseHasOwnerQuorum).mockResolvedValueOnce(false)
    vi.mocked(client.createMlsOwnerApprovalRequestMessage)
      .mockResolvedValueOnce(applicationOutboxEntry())

    await expect(service.closeConversation(conversationId)).resolves.toBeNull()
    expect(client.prepareMlsClose).toHaveBeenCalledWith(
      genesisGroupBytes,
      proposalId,
      expect.stringMatching(/^[0-9]+$/),
    )
    expect(client.createMlsOwnerApprovalRequestMessage).toHaveBeenCalledWith(genesisGroupBytes)
    expect(transport.submitAnonymousMlsMessage).toHaveBeenCalledOnce()
    expect(transport.collectMlsOrderingVotes).not.toHaveBeenCalled()

    vi.mocked(client.mlsCloseHasOwnerQuorum).mockResolvedValueOnce(true)
    await expect(service.reconcilePendingCloses()).resolves.toEqual([finalizedClose()])
    expect(transport.stageMlsMembershipDelivery).toHaveBeenCalledOnce()
    expect(transport.collectMlsOrderingVotes).toHaveBeenCalledWith(pendingClose().voteRequest)
    expect(client.buildMlsCloseCommitRequest).toHaveBeenCalledWith(
      genesisGroupBytes,
      { votes: ['authority'] },
    )
    expect(client.finalizeMlsClose).toHaveBeenCalledWith(
      genesisGroupBytes,
      expect.objectContaining({ blockHash: controlBlockHash }),
    )
  })

  it('keeps private sender policy pending for owner approval and resumes exact finalization', async () => {
    vi.stubGlobal('crypto', {
      randomUUID: () => proposalId,
      getRandomValues: (value: Uint8Array) => value,
    })
    const { client, transport, service } = harness(
      null,
      [activeGenesis()],
      { username: 'alice', server: 'alpha.example' },
    )
    vi.mocked(client.mlsPolicyChangeHasOwnerQuorum).mockResolvedValueOnce(false)
    vi.mocked(client.createMlsOwnerApprovalRequestMessage)
      .mockResolvedValueOnce(applicationOutboxEntry())

    await expect(
      service.setApplicationSenderPolicy(conversationId, 'administrators'),
    ).resolves.toBeNull()
    expect(client.prepareMlsAuthorizationPolicyChange).toHaveBeenCalledWith(
      genesisGroupBytes,
      proposalId,
      {
        policyVersion: 1,
        sequence: 2,
        applicationSenders: 2,
      },
      expect.stringMatching(/^[0-9]+$/),
    )
    expect(client.createMlsOwnerApprovalRequestMessage).toHaveBeenCalledWith(genesisGroupBytes)
    expect(transport.collectMlsOrderingVotes).not.toHaveBeenCalled()

    vi.mocked(client.mlsPolicyChangeHasOwnerQuorum).mockResolvedValueOnce(true)
    await expect(service.reconcilePendingPolicyChanges()).resolves.toEqual([
      finalizedPolicy(),
    ])
    expect(transport.stageMlsMembershipDelivery).toHaveBeenCalledOnce()
    expect(transport.collectMlsOrderingVotes).toHaveBeenCalledWith(
      pendingPolicy().voteRequest,
    )
    expect(client.buildMlsPolicyCommitRequest).toHaveBeenCalledWith(
      genesisGroupBytes,
      { votes: ['authority'] },
    )
    expect(client.finalizeMlsPolicyChange).toHaveBeenCalledWith(
      genesisGroupBytes,
      expect.objectContaining({ blockHash: controlBlockHash }),
    )
    expect(transport.publishMlsDeliveryCapability).toHaveBeenCalledWith(
      expect.objectContaining({
        conversationId,
        incarnation: 1,
        epoch: 1,
        capabilityKind: 'group',
      }),
    )
  })

  it('recovers through owner quorum and atomically installs the exact next incarnation', async () => {
    vi.stubGlobal('crypto', {
      randomUUID: () => proposalId,
      getRandomValues: (value: Uint8Array) => {
        value.set(recoveryGroupBytes)
        return value
      },
    })
    const { client, transport, service } = harness(
      null,
      [recoveryPrevious()],
      { username: 'alice', server: 'alpha.example' },
    )

    await expect(service.recoverConversation(conversationId)).resolves.toEqual(
      finalizedRecovery(),
    )
    expect(client.fetchVerifiedMlsOrderingPolicy).toHaveBeenCalledWith('alpha.example')
    expect(client.fetchVerifiedIdentifiedMlsKeyPackages).toHaveBeenCalledTimes(2)
    expect(client.prepareMlsGroupRecovery).toHaveBeenCalledWith(
      genesisGroupBytes,
      recoveryGroupBytes,
      proposalId,
      [{ canonicalDomain: 'alpha.example' }],
      [expect.objectContaining({
        credential: expect.objectContaining({
          credentialIdentity: 'bobby@beta.example#7',
        }),
      })],
      expect.stringMatching(/^[0-9]+$/),
    )
    expect(transport.recoverMlsConversation).toHaveBeenCalledWith(
      pendingRecovery().request,
    )
    expect(client.finalizeMlsGroupRecovery).toHaveBeenCalledWith(
      genesisGroupBytes,
      expect.objectContaining({ recoveryDigest }),
    )
  })

  it('keeps recovery retry material durable until manual owner quorum arrives', async () => {
    const { client, transport, service } = harness(null, [recoveryPrevious()])
    vi.mocked(client.pendingMlsRecoveries).mockResolvedValue([pendingRecovery()])
    vi.mocked(client.mlsRecoveryHasOwnerQuorum).mockResolvedValueOnce(false)
    vi.mocked(client.createMlsOwnerApprovalRequestMessage)
      .mockResolvedValueOnce(applicationOutboxEntry())

    await expect(service.reconcilePendingRecoveries()).resolves.toEqual([])
    expect(client.createMlsOwnerApprovalRequestMessage).toHaveBeenCalledWith(
      genesisGroupBytes,
    )
    expect(transport.recoverMlsConversation).not.toHaveBeenCalled()

    vi.mocked(client.mlsRecoveryHasOwnerQuorum).mockResolvedValueOnce(true)
    await expect(service.reconcilePendingRecoveries()).resolves.toEqual([
      finalizedRecovery(),
    ])
    expect(transport.recoverMlsConversation).toHaveBeenCalledWith(
      pendingRecovery().request,
    )
  })

  it('never merges local MLS state for a malformed control acknowledgement', async () => {
    const { client, transport, service } = harness(null, [activeGenesis()])
    vi.mocked(transport.commitMlsControlBlock).mockResolvedValueOnce({
      conversationId,
      incarnation: 1,
      height: 2,
      epoch: 1,
      blockHash: controlBlockHash,
      idempotent: false,
    })
    await expect(service.reconcilePendingMembershipChanges()).rejects.toThrow(
      /invalid MLS control-block acknowledgement/,
    )
    expect(client.finalizeMlsMembershipChange).not.toHaveBeenCalled()
  })

  it('replenishes exact durable KeyPackages to the target', async () => {
    const { client, transport, service, lock } = harness()
    await expect(service.maintainKeyPackages(4)).resolves.toBe(20)
    expect(client.generateMlsKeyPackage).toHaveBeenCalledTimes(2)
    expect(lock).toHaveBeenCalledTimes(2)
    expect(transport.publishMlsKeyPackages).toHaveBeenCalledWith({
      protocolVersion: 1,
      manifestVersion: 4,
      deviceId: 7,
      keyPackages: [{ keyPackageRef: 'package' }, { keyPackageRef: 'package' }],
    })
  })

  it('adds and removes only the local account linked-device leaves', async () => {
    vi.stubGlobal('crypto', {
      randomUUID: () => proposalId,
      getRandomValues: (value: Uint8Array) => value,
    })
    const { client, service } = harness(
      null,
      [activeGenesis()],
      { username: 'alice', server: 'alpha.example' },
    )
    vi.mocked(client.fetchVerifiedIdentifiedMlsKeyPackages).mockResolvedValue([{
      wire: {
        deviceId: 8,
        manifestVersion: 2,
        suite: 2,
        keyPackageRef: '55'.repeat(32),
        keyPackage: btoa('package'),
        expiresAt: 1_800_000_000,
      },
      credential: {
        credentialIdentity: 'alice@alpha.example#8',
        credentialPublicKey: [...new Uint8Array(65).fill(4)],
      },
      anonymousDeliveryPublicKey: [...new Uint8Array(65).fill(5)],
    }])

    await expect(service.reconcileLinkedDevices([7, 8])).resolves.toHaveLength(1)
    expect(client.fetchVerifiedIdentifiedMlsKeyPackages).toHaveBeenCalledWith(
      { username: 'alice', server: 'alpha.example' },
      conversationId,
      '1',
      expect.stringMatching(/^[0-9]+$/),
    )
    const addCall = vi.mocked(client.prepareMlsDeviceSync).mock.calls[0]
    expect([...addCall[0]]).toEqual([...genesisGroupBytes])
    expect(addCall[1]).toBe(proposalId)
    const addedPackages = addCall[2] as Array<{
      wire: { deviceId: number }
      credential: { credentialIdentity: string }
    }>
    expect(addedPackages).toHaveLength(1)
    expect(addedPackages[0]).toMatchObject({
      wire: { deviceId: 8 },
      credential: { credentialIdentity: 'alice@alpha.example#8' },
    })
    expect(addCall[3]).toEqual([])
    expect(addCall[4]).toMatch(/^[0-9]+$/)

    vi.mocked(client.mlsGroupDevices).mockResolvedValue([
      {
        address: { username: 'alice', server: 'alpha.example' },
        deviceId: 7,
      },
      {
        address: { username: 'alice', server: 'alpha.example' },
        deviceId: 8,
      },
    ])
    vi.mocked(client.prepareMlsDeviceSync).mockClear()
    vi.mocked(client.fetchVerifiedIdentifiedMlsKeyPackages).mockClear()
    await expect(service.reconcileLinkedDevices([7])).resolves.toHaveLength(1)
    expect(client.fetchVerifiedIdentifiedMlsKeyPackages).not.toHaveBeenCalled()
    const removalCall = vi.mocked(client.prepareMlsDeviceSync).mock.calls[0]
    expect([...removalCall[0]]).toEqual([...genesisGroupBytes])
    expect(removalCall[1]).toBe(proposalId)
    expect(removalCall[2]).toEqual([])
    expect(removalCall[3]).toEqual([8])
    expect(removalCall[4]).toMatch(/^[0-9]+$/)
  })

  it('auto-installs a linked-device Welcome only for an already-active account', async () => {
    const { client, transport, service } = harness(
      null,
      [],
      { username: 'alice', server: 'alpha.example' },
    )
    vi.mocked(transport.listMlsInvitations).mockResolvedValue([])
    vi.mocked(transport.fetchMlsControlHistory).mockResolvedValue({
      bytes: new Uint8Array([123, 125]),
      entryCount: 1,
      nextHeight: '1',
      genesisGroupId: groupId,
    })

    await expect(service.reconcileInboundLinkedDeviceWelcomes()).resolves.toHaveLength(1)
    expect(client.inspectMlsWelcome).toHaveBeenCalledWith(
      new Uint8Array(16).fill(7),
      new Uint8Array(32).fill(9),
    )
    expect(client.joinMlsFromWelcomeWithControlHistory).toHaveBeenCalledWith(
      envelopeId,
      '1',
      sendId,
      new Uint8Array(16).fill(7),
      new Uint8Array(32).fill(9),
      expect.any(Array),
      [new Uint8Array([123, 125])],
    )
    expect(transport.respondMlsInvitation).not.toHaveBeenCalled()
    expect(transport.ackMlsMailbox).toHaveBeenCalledWith(7, [envelopeId])
  })

  it('never auto-installs a Welcome while an account invitation is pending', async () => {
    const { client, transport, service } = harness(null, [])
    await expect(service.reconcileInboundLinkedDeviceWelcomes()).resolves.toEqual([])
    expect(client.inspectMlsWelcome).not.toHaveBeenCalled()
    expect(client.joinMlsFromWelcomeWithControlHistory).not.toHaveBeenCalled()
    expect(transport.ackMlsMailbox).not.toHaveBeenCalled()
  })

  it('fetches anonymous KeyPackages only through the shared proof verifier', async () => {
    const { client, transport, service } = harness()
    const capability = new Uint8Array(16).fill(8)
    await expect(
      service.fetchVerifiedKeyPackages(
        { username: 'bob', server: 'example.test' },
        capability,
      ),
    ).resolves.toHaveLength(1)
    expect(client.fetchVerifiedMlsKeyPackages).toHaveBeenCalledWith(
      { username: 'bob', server: 'example.test' },
      capability,
      expect.stringMatching(/^[0-9]+$/),
    )
    expect(transport.fetchAnonymousMlsKeyPackages).not.toHaveBeenCalled()
  })

  it('stages an anonymous envelope before recording its first durable attempt', async () => {
    vi.stubGlobal('crypto', {
      randomUUID: () => sendId,
      getRandomValues: (value: Uint8Array) => value,
    })
    const { client, transport, service } = harness(null, [activeGenesis()])

    await expect(service.sendText(conversationId, 'federated group message')).resolves.toEqual({
      delivered: true,
      deduplicated: false,
      attempts: 1,
    })

    expect(client.fetchVerifiedMlsKeyPackages).toHaveBeenCalledWith(
      { username: 'bobby', server: 'beta.example' },
      new Uint8Array(16).fill(8),
      expect.stringMatching(/^[0-9]+$/),
    )
    expect(client.stageMlsApplicationDelivery).toHaveBeenCalledOnce()
    expect(client.noteMlsApplicationDeliveryAttempt).toHaveBeenCalledWith(
      sendId,
      'bobby@beta.example',
    )
    expect(transport.submitAnonymousMlsMessage).toHaveBeenCalledWith({
      envelopes: [{ deviceId: 7 }],
    })
    expect(client.markMlsApplicationRecipientDelivered).toHaveBeenCalledWith(
      sendId,
      'bobby@beta.example',
      false,
    )
  })

  it('verifies one application sender leaf without weakening full-roster verification', async () => {
    const { client, transport, service } = harness(null, [activeGenesis()])
    const anonymousEnvelope = {
      deviceId: 7,
      encapsulatedKey: btoa(String.fromCharCode(...new Uint8Array(65).fill(3))),
      ciphertext: btoa(String.fromCharCode(...new Uint8Array([4, 5, 6]))),
    }
    vi.mocked(transport.drainMlsMailbox).mockResolvedValueOnce({
      envelopes: [{
        id: envelopeId,
        cursor: '1',
        deliveryKind: 'anonymous',
        sendId,
        opaqueEnvelope: btoa(JSON.stringify(anonymousEnvelope)),
        serverTimestamp: 1_700_000_000,
      }],
      nextCursor: '1',
    })

    await expect(service.reconcileInboundApplicationMessages()).resolves.toEqual([
      expect.objectContaining({
        message: expect.objectContaining({
          recordId: `in:${envelopeId}`,
          messageId: sendId,
        }),
      }),
    ])
    expect(client.resolveMlsSenderClaim).toHaveBeenCalledWith({
      credentialIdentity: 'alice@example.test#7',
      credentialPublicKey: [...new Uint8Array(65).fill(4)],
    })
    expect(client.resolveMlsWelcomeClaims).not.toHaveBeenCalled()
    expect(client.applyAnonymousMlsApplicationEnvelope).toHaveBeenCalledWith(
      envelopeId,
      '1',
      sendId,
      '1700000000',
      { username: 'bobby', server: 'beta.example' },
      anonymousEnvelope,
      {
        credentialIdentity: 'alice@example.test#7',
        credentialPublicKey: [...new Uint8Array(65).fill(4)],
      },
    )
    expect(transport.ackMlsMailbox).toHaveBeenCalledWith(7, [envelopeId])
  })

  it('joins only with matching verified evidence, then activates and acknowledges', async () => {
    const { client, transport, service } = harness()
    const pending = invitation()
    await expect(service.acceptInvitation(pending)).resolves.toMatchObject({
      serverAccepted: true,
      resumed: false,
    })
    expect(client.resolveMlsWelcomeClaims).toHaveBeenCalledWith([
      {
        credentialIdentity: 'alice@example.test#7',
        credentialPublicKey: [...new Uint8Array(65).fill(4)],
      },
    ])
    expect(client.joinMlsFromWelcomeWithControlHistory).toHaveBeenCalledWith(
      envelopeId,
      '1',
      sendId,
      new Uint8Array(16).fill(7),
      new Uint8Array(32).fill(9),
      expect.any(Array),
      [new Uint8Array([123, 125])],
    )
    expect(transport.fetchMlsControlHistory).toHaveBeenCalledWith(
      conversationId,
      1,
      '0',
      64,
    )
    expect(transport.respondMlsInvitation).toHaveBeenCalledWith({
      conversationId,
      incarnation: 1,
      accept: true,
    })
    expect(transport.ackMlsMailbox).toHaveBeenCalledWith(7, [envelopeId])
  })

  it('accepts only canonical, versioned invitation feedback', async () => {
    const { transport, service } = harness()
    await expect(service.invitationFeedback()).resolves.toEqual([invitationFeedback()])
    expect(transport.listMlsInvitationFeedback).toHaveBeenCalledOnce()

    vi.mocked(transport.listMlsInvitationFeedback).mockResolvedValue([
      { ...invitationFeedback(), member: { username: 'bobby', server: 'BETA.example' } },
    ])
    await expect(service.invitationFeedback()).rejects.toThrow(
      'MLS account address is not canonical',
    )
  })

  it('inspects Welcome claims without joining or acknowledging', async () => {
    const { client, transport, service } = harness()
    await expect(service.inspectInvitation(invitation())).resolves.toMatchObject({
      epoch: 1,
      claimedMembers: [{ credentialIdentity: 'alice@example.test#7' }],
    })
    expect(client.inspectMlsWelcome).toHaveBeenCalledOnce()
    expect(client.resolveMlsWelcomeClaims).not.toHaveBeenCalled()
    expect(client.joinMlsFromWelcomeWithControlHistory).not.toHaveBeenCalled()
    expect(transport.ackMlsMailbox).not.toHaveBeenCalled()
  })

  it('applies, durably receipts, and only then acknowledges an ordered inbound Commit', async () => {
    const { client, transport, service } = harness(null, [activeGenesis()])
    await expect(service.reconcileInboundMembershipCommits()).resolves.toEqual([
      expect.objectContaining({
        group: expect.objectContaining({ epoch: 1 }),
        receipt: expect.objectContaining({ envelopeId, cursor: '1' }),
      }),
    ])
    expect(client.inspectInboundMlsCommit).toHaveBeenCalledWith(
      genesisGroupBytes,
      new Uint8Array(32).fill(9),
    )
    expect(transport.fetchMlsControlHistory).toHaveBeenCalledWith(
      conversationId,
      1,
      '0',
      1,
    )
    expect(client.applyOrderedInboundMlsMembershipCommit).toHaveBeenCalledWith(
      envelopeId,
      '1',
      sendId,
      genesisGroupBytes,
      new Uint8Array(32).fill(9),
      expect.any(Array),
      new Uint8Array([123, 125]),
    )
    expect(transport.ackMlsMailbox).toHaveBeenCalledWith(7, [envelopeId])
    expect(
      vi.mocked(client.applyOrderedInboundMlsMembershipCommit).mock.invocationCallOrder[0],
    ).toBeLessThan(vi.mocked(transport.ackMlsMailbox).mock.invocationCallOrder[0])
  })

  it('verifies and joins a federated recovery before acknowledging its Welcome', async () => {
    const { client, transport, service } = harness(null, [recoveryPrevious()])
    vi.mocked(transport.drainMlsMailbox).mockResolvedValueOnce({
      envelopes: [{
        id: envelopeId,
        cursor: '1',
        deliveryKind: 'membership_control',
        conversationId,
        incarnation: 2,
        sendId,
        opaqueEnvelope: welcome,
        serverTimestamp: Math.floor(Date.now() / 1000),
      }],
      nextCursor: '1',
    })
    const claims = [
      {
        credentialIdentity: 'alice@alpha.example#7',
        credentialPublicKey: [...new Uint8Array(65).fill(4)],
      },
      {
        credentialIdentity: 'bobby@beta.example#7',
        credentialPublicKey: [...new Uint8Array(65).fill(5)],
      },
    ]
    vi.mocked(client.inspectMlsWelcome).mockResolvedValueOnce({
      mlsGroupId: [...recoveryGroupBytes],
      epoch: 1,
      privateControlState: {
        protocolVersion: 1,
        conversationId,
        incarnation: 2,
        height: 0,
        initialEpoch: 1,
        epoch: 1,
      },
      claimedMembers: claims,
    })
    vi.mocked(client.resolveMlsWelcomeClaims).mockResolvedValueOnce(claims)

    await expect(service.reconcileInboundRecoveries()).resolves.toEqual([
      {
        group: finalizedRecovery().group,
        conversation: finalizedRecovery().conversation,
      },
    ])
    expect(transport.fetchMlsRecovery).toHaveBeenCalledWith(conversationId, 2)
    expect(client.joinMlsFromRecoveryWelcome).toHaveBeenCalledWith(
      envelopeId,
      '1',
      sendId,
      recoveryGroupBytes,
      new Uint8Array(32).fill(9),
      claims,
      recoveryStatement(),
    )
    expect(transport.ackMlsMailbox).toHaveBeenCalledWith(7, [envelopeId])
    expect(
      vi.mocked(client.joinMlsFromRecoveryWelcome).mock.invocationCallOrder[0],
    ).toBeLessThan(vi.mocked(transport.ackMlsMailbox).mock.invocationCallOrder[0])
  })

  it('acknowledges a crash-replayed Commit from its durable receipt without parsing it', async () => {
    const { client, transport, service } = harness(null, [activeGenesis()])
    vi.mocked(client.processedMlsControlEnvelope).mockResolvedValueOnce({
      envelopeId,
      cursor: '1',
      sendId,
      conversationId,
      incarnation: 1,
      height: 1,
      epoch: 1,
      blockHash: controlBlockHash,
    })
    await expect(service.reconcileInboundMembershipCommits()).resolves.toEqual([])
    expect(client.inspectInboundMlsCommit).not.toHaveBeenCalled()
    expect(client.applyOrderedInboundMlsMembershipCommit).not.toHaveBeenCalled()
    expect(transport.ackMlsMailbox).toHaveBeenCalledWith(7, [envelopeId])
  })

  it('resumes server activation without rejoining a durable group', async () => {
    const { client, service } = harness({
      mlsGroupId: [...new Uint8Array(16).fill(7)],
      epoch: 1,
    })
    const pending = invitation()
    await expect(service.acceptInvitation(pending)).resolves.toMatchObject({
      serverAccepted: true,
      resumed: true,
    })
    expect(client.joinMlsFromWelcomeWithControlHistory).toHaveBeenCalledOnce()
  })

  it('rejects a verifier result that differs from the inspected Welcome', async () => {
    const { client, service } = harness()
    vi.mocked(client.resolveMlsWelcomeClaims).mockResolvedValueOnce([
      {
        credentialIdentity: 'mallory@example.test#7',
        credentialPublicKey: [...new Uint8Array(65).fill(4)],
      },
    ])
    await expect(service.acceptInvitation(invitation())).rejects.toThrow(
      /roster different/,
    )
    expect(client.joinMlsFromWelcomeWithControlHistory).not.toHaveBeenCalled()
  })
})
