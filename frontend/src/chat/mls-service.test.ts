import { describe, expect, it, vi } from 'vitest'
import { MlsConversationService } from './mls-service'
import type {
  ChatTransportPort,
  LocalMlsGroupState,
  PendingMlsInvitation,
  WasmChatClientHandle,
} from './types'

const conversationId = '11111111-1111-4111-8111-111111111111'
const envelopeId = '22222222-2222-4222-8222-222222222222'
const sendId = '33333333-3333-4333-8333-333333333333'
const groupId = btoa(String.fromCharCode(...new Uint8Array(16).fill(7)))
const welcome = btoa(String.fromCharCode(...new Uint8Array(32).fill(9)))

function invitation(): PendingMlsInvitation {
  return {
    conversationId,
    incarnation: 1,
    mlsGroupId: groupId,
    invitedEpoch: 1,
    expiresAt: Math.floor(Date.now() / 1000) + 3600,
  }
}

function harness(existing: LocalMlsGroupState | null = null) {
  const client = {
    deviceId: 7,
    mlsKeyPackageCount: vi.fn(),
    generateMlsKeyPackage: vi.fn().mockResolvedValue({ keyPackageRef: 'package' }),
    mlsGroupState: vi.fn().mockResolvedValue(existing),
    inspectMlsWelcome: vi.fn().mockResolvedValue({
      mlsGroupId: [...new Uint8Array(16).fill(7)],
      epoch: 1,
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
    fetchVerifiedMlsKeyPackages: vi.fn().mockResolvedValue([
      { wire: { deviceId: 7 }, credential: { credentialIdentity: 'bob@example.test#7' } },
    ]),
    joinMlsFromWelcome: vi.fn().mockResolvedValue({
      mlsGroupId: [...new Uint8Array(16).fill(7)],
      epoch: 1,
    }),
  } as unknown as WasmChatClientHandle
  const transport = {
    mlsKeyPackageCount: vi.fn().mockResolvedValue({ deviceId: 7, available: 18 }),
    publishMlsKeyPackages: vi.fn().mockResolvedValue({ deviceId: 7, available: 20 }),
    listMlsInvitations: vi.fn().mockResolvedValue([invitation()]),
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
    fetchAnonymousMlsKeyPackages: vi.fn(),
  } as unknown as ChatTransportPort
  const lockCalls = vi.fn()
  const lock = async <T>(operation: () => Promise<T>): Promise<T> => {
    lockCalls()
    return await operation()
  }
  return {
    client,
    transport,
    service: new MlsConversationService(client, transport, lock),
    lock: lockCalls,
  }
}

describe('MlsConversationService', () => {
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
    expect(client.joinMlsFromWelcome).toHaveBeenCalledOnce()
    expect(transport.respondMlsInvitation).toHaveBeenCalledWith({
      conversationId,
      incarnation: 1,
      accept: true,
    })
    expect(transport.ackMlsMailbox).toHaveBeenCalledWith(7, [envelopeId])
  })

  it('inspects Welcome claims without joining or acknowledging', async () => {
    const { client, transport, service } = harness()
    await expect(service.inspectInvitation(invitation())).resolves.toMatchObject({
      epoch: 1,
      claimedMembers: [{ credentialIdentity: 'alice@example.test#7' }],
    })
    expect(client.inspectMlsWelcome).toHaveBeenCalledOnce()
    expect(client.resolveMlsWelcomeClaims).not.toHaveBeenCalled()
    expect(client.joinMlsFromWelcome).not.toHaveBeenCalled()
    expect(transport.ackMlsMailbox).not.toHaveBeenCalled()
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
    expect(client.joinMlsFromWelcome).not.toHaveBeenCalled()
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
    expect(client.joinMlsFromWelcome).not.toHaveBeenCalled()
  })
})
