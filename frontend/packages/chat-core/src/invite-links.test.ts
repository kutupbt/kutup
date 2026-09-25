import { describe, expect, it, vi } from 'vitest'
import { InviteLinkService, inviteFragmentFromUrl, inviteLinkUrl } from './invite-links'
import type { MlsConversationService } from './mls-service'
import type {
  ChatTransportPort,
  InviteLinkCrypto,
  InviteLinkOperation,
  InviteLinkResult,
  LocalMlsConversationRecord,
  MlsGroupInviteLink,
  PendingMlsInvitation,
} from './types'

const LINK: MlsGroupInviteLink = { secret: 'c2VjcmV0', host: 'a.test', approvalRequired: false }

/** Readable stand-ins for the WASM functions: "sealing" is JSON. */
const crypto: InviteLinkCrypto = {
  inviteLinkNew: (host, approvalRequired) => ({ secret: 'bmV3', host, approvalRequired }),
  inviteLinkKeys: (link) => ({ linkId: `id:${link.secret}`, manageToken: `m:${link.secret}` }),
  inviteLinkFragment: (link) => `F${link.secret}`,
  inviteLinkParse: () => ({ secret: LINK.secret, host: LINK.host }),
  inviteLinkSealPreview: (_link, preview) => JSON.stringify(preview),
  inviteLinkOpenPreview: (_link, sealed) => JSON.parse(sealed),
  inviteLinkSealRequest: (_link, request) => JSON.stringify(request),
  inviteLinkOpenRequest: (_link, sealed) => JSON.parse(sealed),
  inviteStatusToken: () => 'token',
}

function group(admins: string[], members: string[], link = LINK): LocalMlsConversationRecord {
  const roster = [...admins.map((a) => [a, true] as const), ...members.map((m) => [m, false] as const)]
  return {
    status: 'active',
    request: { genesis: { conversationId: 'g1', incarnation: 1 } },
    currentRoster: roster.map(([address, isAdmin]) => {
      const [username, server] = address.split('@')
      return { address: { username, server }, isAdmin }
    }),
    currentGroupInfo: { sequence: 2, name: 'Hikers', inviteLink: link },
  } as unknown as LocalMlsConversationRecord
}

function harness(record: LocalMlsConversationRecord, requests: Array<{ requester: string; origin: string; at?: number }>) {
  const calls: InviteLinkOperation[] = []
  const transport = {
    callInviteLink: vi.fn(async (_host: string, operation: InviteLinkOperation): Promise<InviteLinkResult> => {
      calls.push(operation)
      if (operation.op === 'requests') {
        return {
          result: 'requests',
          requests: requests.map((request, index) => {
            const [username, server] = request.requester.split('@')
            return {
              requestId: `r${index}`,
              originDomain: request.origin,
              request: JSON.stringify({ requester: { username, server }, createdAtMs: 1 }),
              status: 'pending' as const,
              createdAtMs: request.at ?? Date.now(),
            }
          }),
        }
      }
      return { result: 'done' }
    }),
  } as unknown as ChatTransportPort
  const mls = {
    conversations: vi.fn(async () => [record]),
    addMember: vi.fn(async () => ({})),
    invitations: vi.fn(async (): Promise<PendingMlsInvitation[]> => []),
    acceptInvitation: vi.fn(async () => ({})),
    setGroupInfo: vi.fn(async () => ({ conversation: record })),
  }
  const storage = new Map<string, string>()
  const service = (self: string) => {
    const [username, server] = self.split('@')
    return new InviteLinkService(
      mls as unknown as MlsConversationService,
      transport,
      crypto,
      { username, server },
      {
        getItem: (key) => storage.get(key) ?? null,
        setItem: (key, value) => void storage.set(key, value),
        removeItem: (key) => void storage.delete(key),
      },
    )
  }
  return { calls, transport: transport as unknown as { callInviteLink: ReturnType<typeof vi.fn> }, mls, service, storage }
}

describe('group link URLs', () => {
  it('finds the fragment of any server’s join link', () => {
    const fragment = 'A'.repeat(60)
    expect(inviteFragmentFromUrl(inviteLinkUrl('https://chat.a.test/', fragment))).toBe(fragment)
    expect(inviteFragmentFromUrl(`https://chat.b.test/join#${fragment}`)).toBe(fragment)
    expect(inviteFragmentFromUrl(`https://chat.b.test/c/x#${fragment}`)).toBeNull()
    expect(inviteFragmentFromUrl('https://chat.b.test/join#short')).toBeNull()
    expect(inviteFragmentFromUrl(`javascript:alert(1)//join#${fragment}`)).toBeNull()
  })
})

describe('administrators', () => {
  it('the first administrator adds people when no approval is needed', async () => {
    const h = harness(group(['ali@a.test', 'zed@a.test'], []), [{ requester: 'bob@b.test', origin: 'b.test' }])
    await h.service('ali@a.test').reconcileRequests(true)
    expect(h.mls.addMember).toHaveBeenCalledWith('g1', { username: 'bob', server: 'b.test' })
    expect(h.calls).toContainEqual(expect.objectContaining({ op: 'decide', requestId: 'r0', approve: true }))

    // Another administrator waits, unless the request is old.
    const other = harness(group(['ali@a.test', 'zed@a.test'], []), [{ requester: 'bob@b.test', origin: 'b.test' }])
    const zed = other.service('zed@a.test')
    await zed.reconcileRequests(true)
    expect(other.mls.addMember).not.toHaveBeenCalled()
    expect(zed.joinRequests()).toEqual([{ conversationId: 'g1', requester: 'bob@b.test', createdAtMs: expect.any(Number) }])
    const late = harness(group(['ali@a.test', 'zed@a.test'], []), [{ requester: 'bob@b.test', origin: 'b.test', at: Date.now() - 10 * 60_000 }])
    await late.service('zed@a.test').reconcileRequests(true)
    expect(late.mls.addMember).toHaveBeenCalled()
  })

  it('waits for a decision when approval is needed, and decides for every copy', async () => {
    const h = harness(
      group(['ali@a.test'], [], { ...LINK, approvalRequired: true }),
      [{ requester: 'bob@b.test', origin: 'b.test' }, { requester: 'bob@b.test', origin: 'b.test' }],
    )
    const ali = h.service('ali@a.test')
    await ali.reconcileRequests(true)
    expect(h.mls.addMember).not.toHaveBeenCalled()
    expect(ali.joinRequests()).toHaveLength(1)
    await ali.decide('g1', 'bob@b.test', true)
    expect(h.mls.addMember).toHaveBeenCalledTimes(1)
    expect(h.calls.filter((call) => call.op === 'decide')).toHaveLength(2)
    expect(ali.joinRequests()).toEqual([])
  })

  it('turns away a request naming another server, and approves members', async () => {
    const h = harness(group(['ali@a.test'], ['cem@c.test']), [
      { requester: 'bob@b.test', origin: 'evil.test' },
      { requester: 'cem@c.test', origin: 'c.test' },
    ])
    await h.service('ali@a.test').reconcileRequests(true)
    expect(h.mls.addMember).not.toHaveBeenCalled()
    expect(h.calls).toContainEqual(expect.objectContaining({ op: 'decide', requestId: 'r0', approve: false }))
    expect(h.calls).toContainEqual(expect.objectContaining({ op: 'decide', requestId: 'r1', approve: true }))
  })

  it('members who are not administrators leave the mailbox alone', async () => {
    const h = harness(group(['ali@a.test'], ['bob@b.test']), [{ requester: 'dan@d.test', origin: 'd.test' }])
    await h.service('bob@b.test').reconcileRequests(true)
    expect(h.calls).toEqual([])
  })

  it('a reset stores the new mailbox first and deletes the old one after', async () => {
    const h = harness(group(['ali@a.test'], []), [])
    await h.service('ali@a.test').change('g1', { kind: 'reset' })
    expect(h.calls.map((call) => `${call.op}:${call.linkId}`)).toEqual(['put:id:bmV3', 'delete:id:c2VjcmV0'])
    expect(h.mls.setGroupInfo).toHaveBeenCalledWith('g1', expect.objectContaining({
      name: 'Hikers',
      inviteLink: { secret: 'bmV3', host: 'a.test', approvalRequired: false },
    }))
  })
})

describe('requesters', () => {
  it('accepts the invitation its request led to', async () => {
    const h = harness(group(['ali@a.test'], []), [])
    h.mls.conversations.mockResolvedValue([])
    const bob = h.service('bob@b.test')
    const lookup = {
      link: LINK,
      linkId: 'id:c2VjcmV0',
      preview: { conversationId: 'g1', name: 'Hikers', memberCount: 1, approvalRequired: false },
      member: false,
    }
    h.transport.callInviteLink.mockResolvedValueOnce({ result: 'requested', requestId: 'r9' })
    await bob.requestToJoin(lookup)
    expect(bob.ownRequests()).toEqual([expect.objectContaining({ conversationId: 'g1', requestId: 'r9', status: 'pending' })])

    const invitation = { conversationId: 'g1', incarnation: 1 } as PendingMlsInvitation
    h.mls.invitations.mockResolvedValue([invitation])
    expect(await bob.reconcileOwnRequests()).toBe(true)
    expect(h.mls.acceptInvitation).toHaveBeenCalledWith(invitation)
    expect(bob.ownRequests()).toEqual([])
  })
})
