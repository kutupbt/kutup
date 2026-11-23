// @vitest-environment node
// crates/kutup-mail-client/tests/fixtures/send.json through sendPlan.ts: the
// web app and the Rust client core (the desktop bridge) plan a send alike.
import { readFile } from 'node:fs/promises'
import { describe, expect, it } from 'vitest'
import { everyone, kutupTargets, pgpGroups, SendPlanError, splitRecipients, type KutupLookup, type KutupRecipient, type Scheme } from './sendPlan'

type Member = { address: string; primary: string; encryptionDisabled: boolean }
interface Fixture {
  name: string
  to: string[]
  cc: string[]
  bcc: string[]
  ownDomain: string
  sender: string
  encrypt: boolean
  defaultScheme: Scheme
  lookups: Record<string, KutupLookup['kind']>
  pinnedKeys: string[]
  schemes: Record<string, Scheme>
  protections: Record<string, { kind: string; publicKey?: string }>
  recipients: Record<string, { kind: 'keys'; primary: string; encryptionDisabled: boolean } | { kind: 'group'; members: Member[] } | { kind: 'notKutup' } | { kind: 'disabled' }>
  expect: { error?: { error: string; address: string } } & Record<string, unknown>
}

const fixtures = JSON.parse(await readFile(new URL('../../../../crates/kutup-mail-client/tests/fixtures/send.json', import.meta.url), 'utf8')) as { cases: Fixture[] }

function plan(f: Fixture) {
  const all = everyone(f.to, f.cc, f.bcc)
  const { local, external } = splitRecipients(
    all,
    (a) => a.endsWith(`@${f.ownDomain}`),
    (a) => {
      const kind = f.lookups[a] ?? 'failed'
      return kind === 'keys' ? { kind, encryptionDisabled: false } : { kind }
    },
    (a) => f.pinnedKeys.includes(a),
  )
  const { groups, plain } = pgpGroups(
    external,
    (a) => (['found', 'pinned'].includes(f.protections[a].kind) ? f.protections[a].publicKey! : null),
    (a) => f.protections[a].kind === 'pinnedUnusable',
    f.bcc,
    (a) => f.schemes[a],
    f.defaultScheme,
    f.encrypt,
  )
  const targets = kutupTargets(
    local,
    (a): KutupRecipient => {
      const r = f.recipients[a]
      if (r.kind === 'keys') return { kind: 'keys', keys: { address: a, primary: r.primary, encryptionDisabled: r.encryptionDisabled } }
      if (r.kind === 'group') return { kind: 'group', members: r.members }
      return r
    },
    f.sender,
    f.encrypt,
  )
  return { local, external, groups, plain, targets }
}

describe('the client core’s send fixtures', () => {
  it('has them', () => expect(fixtures.cases.length).toBeGreaterThanOrEqual(10))
  for (const fixture of fixtures.cases) {
    it(fixture.name, () => {
      if (fixture.expect.error) {
        try {
          plan(fixture)
        } catch (error) {
          expect(error).toBeInstanceOf(SendPlanError)
          expect({ error: (error as SendPlanError).error, address: (error as SendPlanError).address }).toEqual(fixture.expect.error)
          return
        }
        throw new Error('sent, expected a refusal')
      }
      expect(plan(fixture)).toEqual(fixture.expect)
    })
  }
})
