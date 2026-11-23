// @vitest-environment node
// The key lookups of crates/kutup-mail-client/tests/fixtures/keys.json
// through this `verified`: the Rust client core (the desktop bridge, the
// native apps) and the web app decide the same.
import { readFile } from 'node:fs/promises'
import { describe, expect, it, vi } from 'vitest'
vi.mock('../../crypto/src/rustWasm', async () => {
  const [{ readFile: read }, module] = await Promise.all([import('node:fs/promises'), import('../../../wasm/crypto-wasm/kutup_crypto_wasm.js')])
  const wasm = await read(new URL('../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm', import.meta.url))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: () => Promise.resolve(module) }
})
vi.mock('@kutup/session/client', () => ({ default: { get: vi.fn() } }))
vi.mock('@kutup/session/store', () => ({ getSession: () => ({ username: 'me', address: 'me@kutup.dev' }) }))

import { verified } from './keys'

interface Fixture {
  name: string
  asked: string
  ownServer: string
  lookup: Parameters<typeof verified>[1] & { keys: { publicKey: string }[] }
  expect: { ok: boolean; address?: string; sequence?: number; primary?: number; all?: number[]; encryptionDisabled?: boolean; disabled?: boolean }
}

const fixtures = JSON.parse(await readFile(new URL('../../../../crates/kutup-mail-client/tests/fixtures/keys.json', import.meta.url), 'utf8')) as { cases: Fixture[] }

describe('the client core’s key fixtures', () => {
  it('has them', () => {
    expect(fixtures.cases.length).toBeGreaterThanOrEqual(15)
    // This page's server is the fixtures' own.
    expect(new Set(fixtures.cases.map((c) => c.ownServer))).toEqual(new Set(['kutup.dev']))
  })

  for (const fixture of fixtures.cases) {
    it(fixture.name, async () => {
      const index = (key: string) => fixture.lookup.keys.findIndex((k) => k.publicKey === key)
      const got = await verified(fixture.asked, fixture.lookup).then(
        (keys) => ({
          ok: true,
          address: keys.address,
          sequence: keys.sequence,
          primary: index(keys.primary),
          all: keys.all.map(index),
          encryptionDisabled: keys.encryptionDisabled,
          disabled: keys.disabled,
        }),
        () => ({ ok: false }),
      )
      expect(got).toEqual(fixture.expect)
    })
  }
})
