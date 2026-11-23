import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Calendar } from '@kutup/calendar-core/api'
import type { DriveIdentity } from '@kutup/drive-core/identity'
import type { MailAccount } from '@kutup/mail-core/api'
import type { Session } from '@kutup/session/store'

// The sharing routes as the plan (docs/plans/calendar-e3.md) shapes them,
// answered here by a stand-in server; the crypto stands in too (Rust's
// vectors cover it), recording what was sealed to whom.

const server = vi.hoisted(() => ({
  members: [] as { accountId: string; address: string; permissions: number; addedAt: string }[],
  invitations: [] as { id: string; accountId: string; address: string; permissions: number; state: string; createdAt: string; expiresAt: string }[],
  keys: [] as { keyGeneration: number; publicKey: string; fingerprint: string; lockedSecretKey: string; passphraseShare: string }[],
  links: [] as { id: string; kind: string; secret: string | null; createdAt: string }[],
  settings: {},
  calls: [] as { method: string; url: string; body?: unknown }[],
  failAccept: false,
}))
vi.mock('@kutup/session/client', () => ({
  default: {
    get: (url: string) => {
      server.calls.push({ method: 'get', url })
      if (url.endsWith('/members')) return Promise.resolve({ data: { members: server.members, invitations: server.invitations } })
      if (url.endsWith('/keys')) return Promise.resolve({ data: { keys: server.keys } })
      if (url.endsWith('/links')) return Promise.resolve({ data: { links: server.links } })
      return Promise.reject(new Error(`unexpected GET ${url}`))
    },
    post: (url: string, body?: unknown) => {
      server.calls.push({ method: 'post', url, body })
      if (url.endsWith('/accept') && server.failAccept) return Promise.reject(new Error('gone'))
      if (url.endsWith('/links')) return Promise.resolve({ data: { ...(body as object), createdAt: 'now' } })
      return Promise.resolve({ data: {} })
    },
    patch: (url: string, body: unknown) => {
      server.calls.push({ method: 'patch', url, body })
      return Promise.resolve({ data: {} })
    },
    delete: (url: string) => {
      server.calls.push({ method: 'delete', url })
      return Promise.resolve({ data: {} })
    },
  },
}))
vi.mock('@kutup/session/apps', () => ({ loadServerSettings: () => Promise.resolve(server.settings) }))
vi.mock('@kutup/session/apiBase', () => ({ resolveApiBase: () => Promise.resolve('/api/v1') }))
vi.mock('@kutup/session/devices', () => ({ ownAccount: () => Promise.resolve('aci:00000000-0000-4000-8000-00000000000a@kutup.test') }))
vi.mock('@kutup/crypto/accountRef', () => ({ accountKeyOf: (ref: { server: string; accountId: string }) => `aci:${ref.accountId}@${ref.server}` }))

const crypto = vi.hoisted(() => ({
  shared: [] as { generation: number; member: unknown }[],
  rotations: [] as unknown[],
}))
vi.mock('@kutup/crypto/calendar', () => ({
  shareCalendarPassphrase: (_owner: unknown, _id: string, own: { keyGeneration: number }, member: { account: string }) => {
    crypto.shared.push({ generation: own.keyGeneration, member })
    return Promise.resolve(`share-${own.keyGeneration}-${member.account}`)
  },
  unlockSharedCalendar: (_member: unknown, owner: { signingPublicKey: string }, lock: { passphraseShare: string }) =>
    owner.signingPublicKey === 'bo-signing'
      ? Promise.resolve({
          fingerprint: lock.passphraseShare,
          openMetadata: (_m: unknown, _id: string, signers: string[]) => ({ name: 'Team', description: '', verified: signers.includes('bo-key') }),
          free: () => undefined,
        })
      : Promise.reject(new Error('not the owner’s share')),
  rotateCalendar: (_owner: unknown, _signer: unknown, _id: string, own: { keyGeneration: number }, rotation: { members: { account: string }[]; links: { linkId: string }[] }) => {
    crypto.rotations.push({ own, rotation })
    return Promise.resolve({
      keyGeneration: own.keyGeneration + 1,
      publicKey: 'P2',
      lockedSecretKey: 'L2',
      fingerprint: 'f2',
      ownShare: 'own2',
      memberShares: rotation.members.map((m) => ({ account: m.account, share: `new-${m.account}` })),
      metadata: { keyPacket: 'k', dataPacket: 'd', signature: 's' },
      links: rotation.links.map((l) => ({ linkId: l.linkId, passphrase: `p-${l.linkId}` })),
    })
  },
  createCalendarLink: (_owner: unknown, _id: string, _linkId: string, shares: { keyGeneration: number }[]) =>
    Promise.resolve({
      urlSecret: 'URLSECRET',
      secret: 'owner-sealed-secret',
      passphrases: shares.map((s) => ({ keyGeneration: s.keyGeneration, sealed: `pp-${s.keyGeneration}` })),
      accessProof: 'PROOF',
    }),
  calendarLinkUrlSecret: (_owner: unknown, _linkId: string, sealed: string) => (sealed === 'mine' ? Promise.resolve('URLSECRET') : Promise.reject(new Error('not the owner’s'))),
  unlockCalendar: () => Promise.resolve({ fingerprint: 'f3', free: () => undefined }),
  sealLinkPurpose: (_calendar: unknown, _signer: unknown, calendarId: string, linkId: string, purpose: string) => ({ keyPacket: 'k', dataPacket: `${calendarId}/${linkId}/${purpose}`, signature: 's' }),
}))

const pins = vi.hoisted(() => ({
  people: new Map<string, unknown>(),
  doubtful: new Set<string>(),
  accepted: [] as string[],
}))
vi.mock('@kutup/drive-core/identityPins', () => {
  class IdentityNotConfirmed extends Error {
    constructor(
      readonly account: string,
      readonly status: { kind: string },
    ) {
      super('not confirmed')
    }
  }
  return {
    IdentityNotConfirmed,
    lookupAddress: (_me: unknown, address: string) => Promise.resolve(pins.people.get(address) ?? null),
    confirmRecipient: (_me: unknown, address: string, _person: unknown, confirmed: boolean) =>
      pins.doubtful.has(address) && !confirmed ? Promise.reject(new IdentityNotConfirmed(address, { kind: 'changed' })) : Promise.resolve({ kind: 'ok' }),
    checkIdentity: (_me: unknown, address: string) => Promise.resolve(pins.doubtful.has(address) ? { kind: 'changed' } : { kind: 'ok', verified: true }),
    sealableDriveKey: (_account: string, key: string) => key,
    acceptIdentity: (_me: unknown, address: string) => {
      pins.accepted.push(address)
      return Promise.resolve()
    },
  }
})
vi.mock('@kutup/drive-core/identity', () => ({ driveIdentityOf: vi.fn() }))
vi.mock('@kutup/mail-core/keys', () => ({
  addressKeys: (address: string) => Promise.resolve({ accountRef: { server: 'kutup.test', accountId: address === 'bo@kutup.test' ? BO : 'someone' }, all: [address === 'bo@kutup.test' ? 'bo-key' : 'other-key'] }),
}))
const records = vi.hoisted(() => ({ filed: [] as string[], forgotten: [] as string[] }))
vi.mock('@kutup/calendar-core/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@kutup/calendar-core/api')>()),
  fileSharedCalendarSettings: (_s: unknown, id: string) => {
    records.filed.push(id)
    server.calls.push({ method: 'record', url: id })
    return Promise.resolve(`record-${id}`)
  },
  forgetCalendarSettings: (_s: unknown, id: string) => {
    records.forgotten.push(id)
    return Promise.resolve()
  },
}))

const BO = '00000000-0000-4000-8000-0000000000b0'
const CY = '00000000-0000-4000-8000-0000000000c0'
const ME = '00000000-0000-4000-8000-00000000000a'

const {
  acceptInvitation,
  AlreadyShared,
  createLink,
  invite,
  leaveCalendar,
  OtherServer,
  PersonNotConfirmed,
  presetOf,
  PRESET_PERMISSIONS,
  RecipientNotFound,
  keyRecipients,
  removeMember,
  rotateKey,
  SelfShare,
  showLink,
  TooManyMembers,
  IdentityNotConfirmed,
} = await import('./client')

const session = { sessionId: 's', accountId: ME, roots: { identityRoot: 'root' } } as unknown as Session
const me = { accountRef: { server: 'kutup.test', accountId: ME }, account: 'ada@kutup.test' } as unknown as DriveIdentity
const account = { key: 'signer' } as unknown as MailAccount
const calendar = { id: 'cal-1', name: 'Team', description: '', owned: true, metadataRest: { v: 1 } } as unknown as Calendar

const person = (accountId: string, address: string, server = 'kutup.test') => ({
  account: address,
  server,
  accountId,
  accountIncarnationId: `inc-${accountId}`,
  driveXwingPublicKey: `xwing-${accountId}`,
  driveSigningPublicKey: `sig-${accountId}`,
  identitySuite: 2,
  username: address.split('@')[0],
  accountAuthorityPublicKey: 'auth',
})
const key = (g: number) => ({ keyGeneration: g, publicKey: 'P', fingerprint: `own-${g}`, lockedSecretKey: 'L', passphraseShare: `own-${g}` })

beforeEach(() => {
  server.members = []
  server.invitations = []
  server.keys = [key(2), key(1)]
  server.links = []
  server.settings = {}
  server.calls = []
  server.failAccept = false
  crypto.shared = []
  crypto.rotations = []
  pins.people = new Map([
    ['bo@kutup.test', person(BO, 'bo@kutup.test')],
    ['cy@kutup.test', person(CY, 'cy@kutup.test')],
    ['ada@kutup.test', person(ME, 'ada@kutup.test')],
    ['far@other.test', person('00000000-0000-4000-8000-0000000000f0', 'far@other.test', 'other.test')],
  ])
  pins.doubtful = new Set()
  pins.accepted = []
  records.filed = []
  records.forgotten = []
})

describe('presets', () => {
  it('are Proton’s two, as bits, and nothing else reads as one', () => {
    expect(presetOf(PRESET_PERMISSIONS.edit)).toBe('edit')
    expect(presetOf(PRESET_PERMISSIONS.view)).toBe('view')
    expect(presetOf(64)).toBeNull()
  })
})

describe('inviting', () => {
  it('seals every live generation to exactly the account looked up, and posts the invitation', async () => {
    await invite(session, me, calendar, ' bo@kutup.test ', 'view')
    expect(crypto.shared.map((s) => s.generation)).toEqual([1, 2])
    expect(crypto.shared[0].member).toEqual({ account: `aci:${BO}@kutup.test`, incarnationId: `inc-${BO}`, xwingPublicKey: `xwing-${BO}` })
    const post = server.calls.find((c) => c.method === 'post')!
    expect(post.url).toBe('/calendar/calendars/cal-1/invitations')
    expect(post.body).toEqual({
      accountId: BO,
      incarnationId: `inc-${BO}`,
      permissions: PRESET_PERMISSIONS.view,
      shares: [
        { keyGeneration: 1, share: `share-1-aci:${BO}@kutup.test` },
        { keyGeneration: 2, share: `share-2-aci:${BO}@kutup.test` },
      ],
    })
  })

  it('refuses no one, oneself, another server, someone already in, and a full calendar', async () => {
    await expect(invite(session, me, calendar, 'nobody@kutup.test', 'view')).rejects.toBeInstanceOf(RecipientNotFound)
    await expect(invite(session, me, calendar, 'ada@kutup.test', 'view')).rejects.toBeInstanceOf(SelfShare)
    await expect(invite(session, me, calendar, 'far@other.test', 'view')).rejects.toBeInstanceOf(OtherServer)
    server.members = [{ accountId: BO, address: 'bo@kutup.test', permissions: 96, addedAt: '' }]
    await expect(invite(session, me, calendar, 'bo@kutup.test', 'view')).rejects.toBeInstanceOf(AlreadyShared)
    server.settings = { calendar: { membersPerCalendar: 1 } }
    await expect(invite(session, me, calendar, 'cy@kutup.test', 'view')).rejects.toBeInstanceOf(TooManyMembers)
    expect(crypto.shared).toEqual([])
  })

  it('stops at a changed identity until the owner confirms it', async () => {
    pins.doubtful.add('bo@kutup.test')
    await expect(invite(session, me, calendar, 'bo@kutup.test', 'edit')).rejects.toBeInstanceOf(IdentityNotConfirmed)
    expect(crypto.shared).toEqual([])
    await invite(session, me, calendar, 'bo@kutup.test', 'edit', true)
    expect(crypto.shared).toHaveLength(2)
  })
})

describe('removing a member', () => {
  it('rotates the key for everyone who stays (pending invitations too) and carries the links over, in one request', async () => {
    server.members = [
      { accountId: BO, address: 'bo@kutup.test', permissions: 96, addedAt: '' },
      { accountId: CY, address: 'cy@kutup.test', permissions: 112, addedAt: '' },
    ]
    server.invitations = [
      { id: 'i1', accountId: 'gone', address: 'gone@kutup.test', permissions: 96, state: 'declined', createdAt: '', expiresAt: '' },
    ]
    pins.people.set('dee@kutup.test', person('00000000-0000-4000-8000-0000000000d0', 'dee@kutup.test'))
    server.invitations.push({ id: 'i2', accountId: '00000000-0000-4000-8000-0000000000d0', address: 'dee@kutup.test', permissions: 96, state: 'pending', createdAt: '', expiresAt: '' })
    server.links = [
      { id: 'full1', kind: 'full', secret: 'mine', createdAt: '' },
      { id: 'busy1', kind: 'busy', secret: null, createdAt: '' },
    ]
    await removeMember(session, me, account, calendar, BO)
    const rotate = server.calls.find((c) => c.url.endsWith('/keys/rotate'))!
    expect(rotate.body).toMatchObject({
      removeAccountId: BO,
      fromKeyGeneration: 2,
      keyGeneration: 3,
      ownShare: 'own2',
      memberShares: [
        { accountId: CY, share: `new-aci:${CY}@kutup.test` },
        { accountId: '00000000-0000-4000-8000-0000000000d0', share: 'new-aci:00000000-0000-4000-8000-0000000000d0@kutup.test' },
      ],
      links: [{ id: 'full1', passphrase: 'p-full1' }],
    })
    // The newest generation is the one rotated from; the names kept as they are.
    expect(crypto.rotations[0]).toMatchObject({ own: { keyGeneration: 2, share: 'own-2' }, rotation: { names: { name: 'Team', description: '', rest: { v: 1 } } } })
  })

  it('stops when someone who stays changed identity, or their address now leads to someone else', async () => {
    server.members = [
      { accountId: BO, address: 'bo@kutup.test', permissions: 96, addedAt: '' },
      { accountId: CY, address: 'cy@kutup.test', permissions: 96, addedAt: '' },
    ]
    pins.doubtful.add('cy@kutup.test')
    await expect(removeMember(session, me, account, calendar, BO)).rejects.toBeInstanceOf(PersonNotConfirmed)
    await removeMember(session, me, account, calendar, BO, new Set([CY]))
    pins.people.set('cy@kutup.test', person('00000000-0000-4000-8000-0000000000e0', 'cy@kutup.test'))
    await expect(removeMember(session, me, account, calendar, BO, new Set([CY]))).rejects.toBeInstanceOf(PersonNotConfirmed)
  })
})

describe('replacing links, and a rotation that is due', () => {
  it('deletes the keyed links before the new key, carries none over, and makes them again under fresh secrets', async () => {
    server.members = [{ accountId: BO, address: 'bo@kutup.test', permissions: 96, addedAt: '' }]
    server.links = [
      { id: 'full1', kind: 'full', secret: 'mine', createdAt: '' },
      { id: 'busy1', kind: 'busy', secret: null, createdAt: '' },
    ]
    const replaced = await removeMember(session, me, account, { ...calendar, keyring: new Map() } as unknown as Calendar, BO, new Set(), true)
    const order = server.calls.map((c) => `${c.method} ${c.url}`)
    const rotateAt = order.indexOf('post /calendar/calendars/cal-1/keys/rotate')
    expect(order.indexOf('delete /calendar/calendars/cal-1/links/full1')).toBeLessThan(rotateAt)
    expect((server.calls[rotateAt].body as { links: unknown[] }).links).toEqual([])
    const made = server.calls.slice(rotateAt).find((c) => c.method === 'post' && c.url.endsWith('/links'))!
    expect(made.body).toMatchObject({ kind: 'full', secret: 'owner-sealed-secret', accessProof: 'PROOF' })
    expect(replaced).toHaveLength(1)
    expect(replaced[0].urls.page).toMatch(/#URLSECRET$/)
    // The busy link needs nothing: it holds no key.
    expect(order).not.toContain('delete /calendar/calendars/cal-1/links/busy1')
  })

  it('rotates with nobody removed when one is due: everyone stays', async () => {
    server.members = [
      { accountId: BO, address: 'bo@kutup.test', permissions: 96, addedAt: '' },
      { accountId: CY, address: 'cy@kutup.test', permissions: 96, addedAt: '' },
    ]
    await rotateKey(session, me, account, calendar, null)
    const rotate = server.calls.find((c) => c.url.endsWith('/keys/rotate'))!
    expect(rotate.body).toMatchObject({ removeAccountId: null, memberShares: [{ accountId: BO }, { accountId: CY }] })
  })

  it('lists who would get the new key, as the pins see them', async () => {
    server.members = [
      { accountId: BO, address: 'bo@kutup.test', permissions: 96, addedAt: '' },
      { accountId: CY, address: 'cy@kutup.test', permissions: 96, addedAt: '' },
    ]
    pins.doubtful.add('cy@kutup.test')
    expect(await keyRecipients(me, 'cal-1', BO)).toEqual([{ accountId: CY, address: 'cy@kutup.test', state: 'changed' }])
  })
})

describe('accepting an invitation', () => {
  const invitation = {
    id: 'inv1',
    calendarId: 'cal-9',
    owner: { accountId: BO, address: 'bo@kutup.test', incarnationId: 'inc', signingPublicKey: 'bo-signing' },
    permissions: PRESET_PERMISSIONS.edit,
    metadata: { keyPacket: 'k', dataPacket: 'd', signature: 's' },
    keys: [key(1), key(2)],
    createdAt: '',
    expiresAt: '',
  }

  it('files the member’s settings before the accept, and takes them back when it fails', async () => {
    await acceptInvitation(session, me, invitation, '#1da583')
    const order = server.calls.map((c) => `${c.method} ${c.url}`)
    expect(order.indexOf('record cal-9')).toBeLessThan(order.indexOf('post /calendar/invitations/inv1/accept'))
    server.failAccept = true
    await expect(acceptInvitation(session, me, invitation, '#1da583')).rejects.toThrow('gone')
    expect(records.forgotten).toEqual(['cal-9'])
  })

  it('refuses an owner whose identity changed until confirmed, then trusts it from now on', async () => {
    pins.doubtful.add('bo@kutup.test')
    await expect(acceptInvitation(session, me, invitation, '#1da583')).rejects.toBeInstanceOf(PersonNotConfirmed)
    expect(records.filed).toEqual([])
    await acceptInvitation(session, me, invitation, '#1da583', true)
    expect(pins.accepted).toEqual(['bo@kutup.test'])
  })

  it('refuses a share its owner did not sign, and a name signed by someone else', async () => {
    await expect(acceptInvitation(session, me, { ...invitation, owner: { ...invitation.owner, signingPublicKey: 'eve-signing' } }, '#1da583')).rejects.toThrow()
    await expect(acceptInvitation(session, me, { ...invitation, owner: { ...invitation.owner, address: 'eve@kutup.test' } }, '#1da583')).rejects.toThrow()
    expect(records.filed).toEqual([])
  })
})

describe('links', () => {
  it('makes a busy link with no key, and a full one whose secret stays in the fragment', async () => {
    const busy = await createLink(session, account, calendar, 'busy')
    expect(server.calls.at(-1)!.body).toEqual({ id: busy.link.id, kind: 'busy', purpose: null })
    expect(busy.urls.ics).toMatch(/\/api\/v1\/calendar\/links\/.+\/calendar\.ics$/)
    const full = await createLink(session, account, calendar, 'full')
    const body = server.calls.at(-1)!.body as Record<string, unknown>
    expect(body).toMatchObject({ kind: 'full', secret: 'owner-sealed-secret', accessProof: 'PROOF', passphrases: [{ keyGeneration: 1 }, { keyGeneration: 2 }] })
    expect(JSON.stringify(body)).not.toContain('URLSECRET')
    expect(full.urls.page).toMatch(/\/l\/.+#URLSECRET$/)
  })

  it('seals the owner’s label for the link, bound to the calendar and the link, and sends none when there is none', async () => {
    const labelled = await createLink(session, account, calendar, 'busy', '  Family  ')
    expect((server.calls.at(-1)!.body as { purpose: unknown }).purpose).toEqual({ keyPacket: 'k', dataPacket: `cal-1/${labelled.link.id}/Family`, signature: 's' })
    await createLink(session, account, calendar, 'busy', '   ')
    expect((server.calls.at(-1)!.body as { purpose: unknown }).purpose).toBeNull()
  })

  it('puts a query link’s key in the address only where the server allows such links', async () => {
    const query = await createLink(session, account, calendar, 'query')
    expect(query.urls.ics).toMatch(/calendar\.ics\?key=URLSECRET$/)
    server.settings = { calendar: { queryLinksAllowed: false } }
    await expect(createLink(session, account, calendar, 'query')).rejects.toThrow()
  })

  it('shows a keyed link again from the owner’s own envelope, and stops at the site’s count', async () => {
    const urls = await showLink(session, calendar, { id: 'l1', kind: 'full', secret: 'mine', createdAt: '' })
    expect(urls.page).toMatch(/\/l\/l1#URLSECRET$/)
    server.settings = { calendar: { linksPerCalendar: 1 } }
    server.links = [{ id: 'l1', kind: 'busy', secret: null, createdAt: '' }]
    await expect(createLink(session, account, calendar, 'busy')).rejects.toThrow('at most 1')
  })
})

describe('leaving', () => {
  it('leaves a calendar someone else owns, then drops its record; an owner can’t leave', async () => {
    await leaveCalendar(session, { ...calendar, owned: false })
    expect(server.calls.at(-1)).toEqual({ method: 'delete', url: '/calendar/calendars/cal-1/members/me' })
    expect(records.forgotten).toEqual(['cal-1'])
    await expect(leaveCalendar(session, calendar)).rejects.toThrow()
  })
})
