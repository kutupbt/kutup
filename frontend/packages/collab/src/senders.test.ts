// @vitest-environment node
// Recipients verify senders (docs/plans/one-device-list.md §8, slice 3), on
// the real Rust rules: a home relaying a frame of a device the sender's head
// doesn't list, or signed under another key, has it dropped; a logged frame
// counts under the manifest it names; a reset account is refused.
import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@kutup/crypto/rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../../wasm/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL('../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm', import.meta.url))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: async () => module }
})

/** The sender account's chain as its server serves it; the head is the last. */
let chain: import('@kutup/crypto/accountManifest').AccountManifest[] = []
vi.mock('@kutup/session/devices', () => ({
  fetchManifest: async () => chain.at(-1) ?? null,
  fetchManifestHistory: async (_account: string, from: number, to: number) =>
    chain.filter((m) => m.sequence >= from && m.sequence <= to),
}))
const kept: unknown[] = []
vi.mock('@kutup/session/manifestPins', () => ({
  manifestPin: async () => null,
  keepManifestPin: async (pin: unknown) => void kept.push(pin),
}))

import { listDeviceInManifest, removeDevicesFromManifest, type ManifestDevice } from '@kutup/crypto/accountManifest'
import { toBase64 } from '@kutup/crypto/base64'
import { generateSigningKey } from '@kutup/crypto/signing'
import { encryptCollabFrame } from './cryptoFrame'
import { KIND } from './envelope'
import { SenderCheck, type SenderRefusal } from './senders'

const SERVER = 'kutup.example'
const ACCOUNT_ID = '22222222-2222-4222-8222-222222222222'
const ACCOUNT = `aci:${ACCOUNT_ID}@${SERVER}`
const MASTER_KEY = toBase64(new Uint8Array(32).fill(7))
const FILE_KEY = new Uint8Array(32).fill(0x41)
const binding = { fileId: '11111111-1111-4111-8111-111111111111', keyGeneration: 1 }

function delivered(frame: Uint8Array): Uint8Array {
  const name = new TextEncoder().encode(SERVER)
  const id = Uint8Array.from(ACCOUNT_ID.replace(/-/g, '').match(/../g)!.map((h) => parseInt(h, 16)))
  const out = new Uint8Array(2 + name.length + id.length + frame.length)
  out[1] = name.length
  out.set(name, 2)
  out.set(id, 2 + name.length)
  out.set(frame, 2 + name.length + id.length)
  return out
}

type Key = Awaited<ReturnType<typeof generateSigningKey>>

function editor(deviceId: number, key: Key): ManifestDevice {
  return { deviceId, kind: 'editor', frameKey: toBase64(key.publicKey), session: 'ab'.repeat(32) }
}

async function frame(deviceId: number, manifestSequence: number, key: Key, sequence = 1n): Promise<Uint8Array> {
  return delivered(
    await encryptCollabFrame(
      new TextEncoder().encode('an edit'),
      KIND.YJS_UPDATE,
      { ...binding, docKeyId: 1, sequence },
      FILE_KEY,
      { deviceId, account: ACCOUNT, manifestSequence: BigInt(manifestSequence), keypair: key },
    ),
  )
}

async function list(entry: ManifestDevice) {
  chain.push(await listDeviceInManifest(chain.at(-1) ?? null, entry, '2026-10-27T00:00:00Z', MASTER_KEY, ACCOUNT))
}

describe('SenderCheck', () => {
  let one: Key
  let two: Key
  beforeEach(async () => {
    chain = []
    kept.length = 0
    one = await generateSigningKey()
    two = await generateSigningKey()
    await list(editor(1, one)) // 1: device 1
    await list(editor(2, two)) // 2: devices 1 and 2
  })

  function check(verdict: 'pinned' | 'changed' | 'unknown' = 'unknown') {
    const refused: SenderRefusal[] = []
    const senders = new SenderCheck({
      authority: async () => verdict,
      onRefused: (refusal) => refused.push(refusal),
    })
    return { senders, refused: () => refused }
  }

  it('takes a listed device signed with its key, and pins the head', async () => {
    const { senders, refused } = check()
    expect(await senders.verify(await frame(1, 1, one), true)).toBe(true)
    expect(await senders.verify(await frame(2, 2, two), true)).toBe(true)
    expect(refused()).toEqual([])
    expect(kept).toHaveLength(1)
    senders.close()
  })

  it("drops a frame the head doesn't list, or one under another key", async () => {
    const { senders, refused } = check()
    expect(await senders.verify(await frame(3, 2, two), true)).toBe(false)
    expect(await senders.verify(await frame(2, 2, one), true)).toBe(false)
    await vi.waitFor(() => expect(refused()).toEqual([{ account: ACCOUNT, name: ACCOUNT, reason: 'unverified' }]))
    senders.close()
  })

  it("drops a removed device's live frames and keeps its logged ones", async () => {
    chain.push(await removeDevicesFromManifest(chain.at(-1)!, [2], '2026-10-27T00:02:00Z', MASTER_KEY))
    const { senders } = check()
    const old = await frame(2, 2, two)
    // Live: the head (3) no longer lists device 2.
    expect(await senders.verify(old, true)).toBe(false)
    // From the log: made under manifest 2, which listed it.
    expect(await senders.verify(old, false)).toBe(true)
    senders.close()
  })

  it("refuses a reset account's frames", async () => {
    const { senders, refused } = check('changed')
    expect(await senders.verify(await frame(1, 1, one), true)).toBe(false)
    await vi.waitFor(() => expect(refused()[0]?.reason).toBe('reset'))
    senders.close()
  })
})
