// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'
vi.mock('../../crypto/src/rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../../wasm/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL('../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm', import.meta.url))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: () => Promise.resolve(module) }
})
const get = vi.hoisted(() => vi.fn())
vi.mock('@kutup/session/client', () => ({ default: { get } }))
// What the pin list says (drive-core's own tests cover how it decides).
type Verdict = { kind: string; now?: string }
const pins: { verdict: Verdict } = vi.hoisted(() => ({ verdict: { kind: 'unknown' } }))
const groupPins = vi.hoisted(() => ({ verdict: { kind: 'new' }, pinned: false, checked: [] as unknown[], accepted: [] as unknown[] }))
vi.mock('@kutup/drive-core/identityPins', () => ({
  pinnedVerdict: vi.fn(() => Promise.resolve(pins.verdict)),
  checkGroup: vi.fn((_me: unknown, server: string, groupId: string, chain: unknown) => {
    groupPins.checked.push({ server, groupId, chain })
    return Promise.resolve(groupPins.verdict)
  }),
  isGroupPinned: vi.fn(() => Promise.resolve(groupPins.pinned)),
  acceptGroup: vi.fn((_me: unknown, server: string, groupId: string, chain: unknown) => {
    groupPins.accepted.push({ server, groupId, chain })
    return Promise.resolve()
  }),
}))
vi.mock('@kutup/drive-core/identity', () => ({ driveIdentityOf: vi.fn(() => Promise.resolve({})) }))
vi.mock('@kutup/session/store', () => ({ getSession: () => ({ username: 'me' }) }))
// The device's revision guard, in memory: the highest key-list sequence seen per address and signer.
const seen = vi.hoisted(() => new Map<string, number>())
vi.mock('@kutup/crypto/revisionGuard', async (importActual) => {
  const actual = await importActual<typeof import('@kutup/crypto/revisionGuard')>()
  return {
    ...actual,
    revisionGuard: () => ({
      accept: (scope: string, id: string, revision: number) => {
        const before = seen.get(`${scope}/${id}`) ?? 0
        if (revision < before) return Promise.reject(new actual.OlderThanSeenError(scope, revision, before))
        seen.set(`${scope}/${id}`, revision)
        return Promise.resolve()
      },
    }),
  }
})

import {
  deriveAccountIdentityKeys,
  generateMailAddressKey,
  MAIL_KEY_FLAGS,
  newMailGroupSigner,
  signMailGroupKeyList,
  signMailKeyList,
  toBase64,
  type GroupSignerHolder,
  type SignedMailKeyList,
} from '@kutup/crypto'
import { acceptGroupKeys, addressKeys, forgetKeys, GroupKeysChanged, KeysIdentityChanged, UnverifiedKeys, verified } from './keys'

/** What `GET /api/mail/keys` answers for `address` (as stored), its newest list naming `listed`. */
async function lookupOf(master: string, binding: string, address: string, listed = address) {
  const key = await generateMailAddressKey(master, binding, address)
  const list = await signMailKeyList(master, {
    address: listed,
    sequence: 1,
    issuedAt: '2026-10-14T12:00:00Z',
    keys: [{ fingerprint: key.fingerprint, sha256Fingerprint: key.sha256Fingerprint, primary: true, flags: MAIL_KEY_FLAGS.notCompromised | MAIL_KEY_FLAGS.notObsolete }],
  })
  const identity = await deriveAccountIdentityKeys(master)
  return {
    address,
    server: 'kutup.dev',
    accountId: '3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70',
    accountAuthorityPublicKey: identity.authorityPublicKey,
    keys: [{ fingerprint: key.fingerprint, sha256Fingerprint: key.sha256Fingerprint, publicKey: key.publicKey, primary: true, flags: 3 }],
    keyLists: [{ data: list.data, signature: list.signature }],
  }
}

describe('an address’s keys', () => {
  const master = toBase64(crypto.getRandomValues(new Uint8Array(32)))
  const binding = crypto.randomUUID()

  it('are the current address’s, asked in any spelling', async () => {
    const lookup = await lookupOf(master, binding, 'ada_l@kutup.dev')
    for (const asked of ['ada_l@kutup.dev', 'ada.l@kutup.dev', 'Ada-L@Kutup.dev', 'adal@kutup.dev']) {
      const keys = await verified(asked, lookup)
      expect(keys.address).toBe('ada_l@kutup.dev')
      expect(keys.primary).toBe(lookup.keys[0].publicKey)
    }
  })

  it('are refused when the newest list names another address of the account', async () => {
    // After a rename to `ada_lovelace`, the old address still receives with
    // its own list: a list of the new address served for it is refused.
    const lookup = await lookupOf(master, binding, 'ada_l@kutup.dev')
    await expect(verified('ada.l@kutup.dev', lookup)).resolves.toMatchObject({ address: 'ada_l@kutup.dev' })
    const other = await lookupOf(master, binding, 'ada_l@kutup.dev', 'ada_lovelace@kutup.dev')
    await expect(verified('ada_l@kutup.dev', other)).rejects.toThrow()
  })

  it('are refused when the answer is another address', async () => {
    const lookup = await lookupOf(master, binding, 'ada_l@kutup.dev')
    await expect(verified('ada_l@kutup.dev', { ...lookup, server: 'other.dev' })).rejects.toBeInstanceOf(UnverifiedKeys)
    await expect(verified('bob@kutup.dev', lookup)).rejects.toBeInstanceOf(UnverifiedKeys)
    await expect(verified('ada_l@other.dev', lookup)).rejects.toBeInstanceOf(UnverifiedKeys)
  })
})

describe('an address’s keys against the pin list', () => {
  const master = toBase64(crypto.getRandomValues(new Uint8Array(32)))
  const binding = crypto.randomUUID()

  async function lookedUp(verdict: { kind: string; now?: string; name?: string }) {
    pins.verdict = verdict
    forgetKeys()
    const lookup = await lookupOf(master, binding, 'ada_l@kutup.dev')
    get.mockResolvedValueOnce({ data: lookup })
    return addressKeys('ada_l@kutup.dev')
  }

  it('refuses another authority for a pinned person', async () => {
    await expect(lookedUp({ kind: 'changed' })).rejects.toBeInstanceOf(KeysIdentityChanged)
  })

  it('refuses someone else at a name a known person holds, naming where that person is', async () => {
    await expect(lookedUp({ kind: 'someoneElse', now: 'ada_lovelace@kutup.dev' })).rejects.toMatchObject({
      now: 'ada_lovelace@kutup.dev',
    })
    await expect(lookedUp({ kind: 'someoneElse' })).rejects.toBeInstanceOf(KeysIdentityChanged)
  })

  it('takes a pinned account, shown by its own name, and someone never met', async () => {
    await expect(lookedUp({ kind: 'pinned', name: 'mal@kutup.dev' })).resolves.toMatchObject({
      address: 'ada_l@kutup.dev',
      knownAs: 'mal@kutup.dev',
    })
    await expect(lookedUp({ kind: 'pinned' })).resolves.not.toHaveProperty('knownAs')
    await expect(lookedUp({ kind: 'unknown' })).resolves.toMatchObject({ address: 'ada_l@kutup.dev' })
  })
})

describe('an address’s key lists against what this device has seen', () => {
  const master = toBase64(crypto.getRandomValues(new Uint8Array(32)))
  const binding = crypto.randomUUID()

  it('refuses a chain shorter than one seen before (a rollback)', async () => {
    pins.verdict = { kind: 'unknown' }
    forgetKeys()
    const first = await lookupOf(master, binding, 'roll_back@kutup.dev')
    const key = await generateMailAddressKey(master, binding, 'roll_back@kutup.dev')
    const { verifyMailKeyList } = await import('@kutup/crypto')
    const one = await verifyMailKeyList(first.keyLists[0], first.accountAuthorityPublicKey)
    const second = await signMailKeyList(master, {
      address: 'roll_back@kutup.dev',
      sequence: 2,
      previousHash: one.hash,
      issuedAt: '2026-10-15T12:00:00Z',
      keys: [
        { ...one.keys[0], primary: false },
        { fingerprint: key.fingerprint, sha256Fingerprint: key.sha256Fingerprint, primary: true, flags: MAIL_KEY_FLAGS.notCompromised | MAIL_KEY_FLAGS.notObsolete },
      ].sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1)),
    })
    const longer = {
      ...first,
      keys: [...first.keys, { fingerprint: key.fingerprint, sha256Fingerprint: key.sha256Fingerprint, publicKey: key.publicKey, primary: true, flags: 3 }].map((k) =>
        k.fingerprint === key.fingerprint ? k : { ...k, primary: false },
      ),
      keyLists: [...first.keyLists, { data: second.data, signature: second.signature }],
    }
    get.mockResolvedValueOnce({ data: longer })
    await expect(addressKeys('roll_back@kutup.dev')).resolves.toMatchObject({ sequence: 2 })
    // The server hands back the first list alone: refused, not used.
    forgetKeys()
    get.mockResolvedValueOnce({ data: first })
    await expect(addressKeys('roll_back@kutup.dev')).rejects.toBeInstanceOf(UnverifiedKeys)
  })
})

describe('a shared mailbox’s keys against the pin list', () => {
  // Real chains, signed in WASM by the mailbox's own signers.
  const master = toBase64(crypto.getRandomValues(new Uint8Array(32)))
  const binding = crypto.randomUUID()
  const groupId = '2b3c4d5e-6f70-4182-93a4-b5c6d7e8f901'
  const manager = { server: 'kutup.dev', accountId: '3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70' }

  interface Chain {
    firstSigner: string
    lists: SignedMailKeyList[]
    handovers: string[]
    keys: { fingerprint: string; sha256Fingerprint: string; publicKey: string; primary: boolean; flags: number }[]
  }

  /** A mailbox's chain of `count` lists from a new signer; the key the lists name is real. */
  async function newChain(count: number): Promise<Chain & { holder: GroupSignerHolder }> {
    const identity = await deriveAccountIdentityKeys(master)
    const key = await generateMailAddressKey(master, binding, 'team@kutup.dev')
    const entry = { fingerprint: key.fingerprint, sha256Fingerprint: key.sha256Fingerprint, primary: true, flags: MAIL_KEY_FLAGS.notCompromised | MAIL_KEY_FLAGS.notObsolete }
    const first = await newMailGroupSigner(
      groupId,
      [{ account: manager, incarnationId: identity.incarnationId, hpkePublicKey: identity.driveHpkePublicKey }],
      { address: 'team@kutup.dev', sequence: 1, issuedAt: '2026-10-16T12:00:00Z', keys: [entry] },
    )
    const holder: GroupSignerHolder = { account: manager, hpkePrivateKey: identity.driveHpkePrivateKey, groupId, signer: first.publicKey, signingShare: first.shares[0] }
    const lists = [first.keyList]
    for (let sequence = 2; sequence <= count; sequence++) {
      lists.push(await signMailGroupKeyList(holder, { address: 'team@kutup.dev', sequence, previousHash: lists.at(-1)!.hash, issuedAt: '2026-10-16T12:00:00Z', keys: [entry] }))
    }
    return { firstSigner: first.publicKey, lists, handovers: [], holder, keys: [{ ...entry, publicKey: key.publicKey }] }
  }

  function answer(chain: Chain) {
    return {
      address: 'team@kutup.dev',
      server: 'kutup.dev',
      groupId,
      firstSigner: chain.firstSigner,
      keys: chain.keys,
      keyLists: chain.lists.map(({ data, signature }) => ({ data, signature })),
      ...(chain.handovers.length > 0 ? { signerHandovers: chain.handovers } : {}),
    }
  }

  async function asked(chain: Chain) {
    forgetKeys()
    get.mockResolvedValueOnce({ data: answer(chain) })
    return addressKeys('team@kutup.dev')
  }

  it('holds the mailbox to its own group signer, by its id, never to a person', async () => {
    groupPins.verdict = { kind: 'new' }
    groupPins.checked = []
    const chain = await newChain(2)
    const keys = await asked(chain)
    expect(keys).toMatchObject({ address: 'team@kutup.dev', sequence: 2, authorityPublicKey: chain.firstSigner, group: { server: 'kutup.dev', groupId, signers: [chain.firstSigner] } })
    expect(keys).not.toHaveProperty('accountRef')
    expect(groupPins.checked).toEqual([
      { server: 'kutup.dev', groupId, chain: { signers: [chain.firstSigner], digests: chain.lists.map((list) => list.hash) } },
    ])
  })

  it('follows a handover to a new signer as the same chain', async () => {
    groupPins.verdict = { kind: 'pinned' }
    groupPins.checked = []
    const chain = await newChain(2)
    const identity = await deriveAccountIdentityKeys(master)
    const next = await newMailGroupSigner(
      groupId,
      [{ account: manager, incarnationId: identity.incarnationId, hpkePublicKey: identity.driveHpkePublicKey }],
      { address: 'team@kutup.dev', sequence: 3, previousHash: chain.lists[1].hash, issuedAt: '2026-10-16T12:00:00Z', keys: chain.keys.map(({ publicKey: _key, ...entry }) => entry) },
      { holder: chain.holder, previousListHash: chain.lists[1].hash },
    )
    const handedOver = { ...chain, lists: [...chain.lists, next.keyList], handovers: [next.handover!] }
    const keys = await asked(handedOver)
    expect(keys.authorityPublicKey).toBe(next.publicKey)
    expect(groupPins.checked).toMatchObject([{ chain: { signers: [chain.firstSigner, next.publicKey] } }])
  })

  it('says a changed signer is a change the sender may accept, then sends', async () => {
    groupPins.verdict = { kind: 'changed' }
    groupPins.accepted = []
    // An administrator's new chain, from list 1 under another signer.
    const restarted = await newChain(1)
    const error = await asked(restarted).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(GroupKeysChanged)
    expect(error).not.toBeInstanceOf(KeysIdentityChanged)
    expect((error as GroupKeysChanged).chain).toMatchObject({ groupId, signers: [restarted.firstSigner] })
    await acceptGroupKeys(error as GroupKeysChanged)
    expect(groupPins.accepted).toEqual([{ server: 'kutup.dev', groupId, chain: { signers: [restarted.firstSigner], digests: [restarted.lists[0].hash] } }])
  })

  it('says a known mailbox whose chain does not hold has changed, never a silent failure', async () => {
    // A third list signed by another signer with no handover: refused by the chain check.
    const chain = await newChain(2)
    const other = await newChain(1)
    const forged = await signMailGroupKeyList(other.holder, {
      address: 'team@kutup.dev',
      sequence: 3,
      previousHash: chain.lists[1].hash,
      issuedAt: '2026-10-16T12:00:00Z',
      keys: chain.keys.map(({ publicKey: _key, ...entry }) => entry),
    })
    const broken = { ...chain, lists: [...chain.lists, forged] }
    groupPins.pinned = true
    const error = await asked(broken).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(GroupKeysChanged)
    expect((error as GroupKeysChanged).chain).toBeUndefined()
    await expect(acceptGroupKeys(error as GroupKeysChanged)).rejects.toThrow()
    // One never met: the keys are simply not usable.
    groupPins.pinned = false
    const unknown = await asked(broken).catch((e: unknown) => e)
    expect(unknown).toBeInstanceOf(UnverifiedKeys)
    expect(unknown).not.toBeInstanceOf(GroupKeysChanged)
  })

  it('refuses an older list of the same mailbox than this device has seen', async () => {
    groupPins.verdict = { kind: 'pinned' }
    const chain = await newChain(3)
    await asked(chain)
    await expect(asked({ ...chain, lists: chain.lists.slice(0, 2) })).rejects.toBeInstanceOf(UnverifiedKeys)
  })
})

describe('a shared mailbox’s key lists', () => {
  it('are its signers’ chain, and a chain cut back to before a handover is refused', async () => {
    const { deriveAccountIdentityKeys: derive, generateMailGroupKey, newMailGroupSigner, signMailGroupKeyList } = await import('@kutup/crypto')
    // No address pin is consulted for a shared mailbox: a person's changed pin there does not apply.
    pins.verdict = { kind: 'changed' }
    groupPins.verdict = { kind: 'pinned' }
    forgetKeys()
    const groupId = crypto.randomUUID()
    const address = 'hr_team@kutup.dev'
    const master = toBase64(crypto.getRandomValues(new Uint8Array(32)))
    const owner = await derive(master)
    const account = { server: 'kutup.dev', accountId: crypto.randomUUID() }
    const member = { account, incarnationId: owner.incarnationId, hpkePublicKey: owner.driveHpkePublicKey }
    const k1 = await generateMailGroupKey(address, groupId, [member])
    const entry = (key: { fingerprint: string; sha256Fingerprint: string }, primary: boolean) => ({
      fingerprint: key.fingerprint,
      sha256Fingerprint: key.sha256Fingerprint,
      primary,
      flags: primary ? MAIL_KEY_FLAGS.notCompromised | MAIL_KEY_FLAGS.notObsolete : MAIL_KEY_FLAGS.notCompromised,
    })
    const first = await newMailGroupSigner(groupId, [member], { address, sequence: 1, issuedAt: '2026-10-16T12:00:00Z', keys: [entry(k1, true)] })
    const holder = { account, hpkePrivateKey: owner.driveHpkePrivateKey, groupId, signer: first.publicKey, signingShare: first.shares[0] }
    const k2 = await generateMailGroupKey(address, groupId, [member])
    const keysAfter = [entry(k1, false), entry(k2, true)].sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1))
    const second = await signMailGroupKeyList(holder, { address, sequence: 2, previousHash: first.keyList.hash, issuedAt: '2026-10-16T12:00:00Z', keys: keysAfter })
    // A handover to a new signer at list 3.
    const third = await newMailGroupSigner(
      groupId,
      [member],
      { address, sequence: 3, previousHash: second.hash, issuedAt: '2026-10-16T12:00:00Z', keys: keysAfter },
      { holder, previousListHash: second.hash },
    )
    const row = (key: { fingerprint: string; sha256Fingerprint: string; publicKey: string }, primary: boolean) => ({
      fingerprint: key.fingerprint,
      sha256Fingerprint: key.sha256Fingerprint,
      publicKey: key.publicKey,
      primary,
      flags: 3,
    })
    const lookup = (lists: { data: string; signature: string }[], handovers: string[]) => ({
      address,
      server: 'kutup.dev',
      groupId,
      firstSigner: first.publicKey,
      keys: [row(k2, true), row(k1, false)],
      keyLists: lists,
      ...(handovers.length ? { signerHandovers: handovers } : {}),
    })
    const full = lookup([first.keyList, second, third.keyList], [third.handover!])
    get.mockResolvedValueOnce({ data: full })
    const keys = await addressKeys(address)
    expect(keys.sequence).toBe(3)
    expect(keys.group?.signers).toEqual([first.publicKey, third.publicKey])
    // The server serves the chain cut back to before the handover: older than seen.
    forgetKeys()
    get.mockResolvedValueOnce({ data: lookup([first.keyList, second], []) })
    await expect(addressKeys(address)).rejects.toBeInstanceOf(UnverifiedKeys)
    // A list from the old signer after its handover never verifies.
    const fork = await signMailGroupKeyList(holder, { address, sequence: 3, previousHash: second.hash, issuedAt: '2026-10-16T12:00:00Z', keys: keysAfter })
    await expect(verified(address, lookup([first.keyList, second, fork], [third.handover!]))).rejects.toBeInstanceOf(UnverifiedKeys)
  })
})
