import { describe, expect, it, vi } from 'vitest'
import { NoKutupAddress } from './keys'

vi.mock('./keys', async (original) => ({
  ...(await original<typeof import('./keys')>()),
  addressKeys: (email: string) => {
    if (email === 'bob@kutup.test') return Promise.resolve({ address: email, accountRef: { server: 'kutup.test' }, primary: 'key' })
    if (email === 'carol@other.test') return Promise.resolve({ address: email, accountRef: { server: 'other.test' }, primary: 'key' })
    return Promise.reject(new NoKutupAddress(email))
  },
}))

const { ForwardeeRefused, forwardeeActions, forwarderActions, forwardingKindOf } = await import('./forwardings')
type MailForwarding = import('./forwardings').MailForwarding

const forwarding = (state: MailForwarding['state'], kind: MailForwarding['kind']): MailForwarding => ({
  id: 'f',
  kind,
  state,
  forwarderAddress: 'a@kutup.test',
  forwardeeEmail: 'b@example.com',
  match: 'all',
  conditions: [],
  skipped: 0,
  notice: null,
  createdAt: '2026-10-19T00:00:00Z',
  expiresAt: null,
})

describe('what each side may do, by state (Proton’s table)', () => {
  it('lets the forwarder edit, pause, resume, re-enable and send again where Proton does', () => {
    expect(forwarderActions(forwarding('pending', 'outside'))).toEqual(['edit', 'reinvite', 'delete'])
    expect(forwarderActions(forwarding('pending', 'end_to_end'))).toEqual(['edit', 'delete'])
    expect(forwarderActions(forwarding('active', 'end_to_end'))).toEqual(['edit', 'pause', 'delete'])
    expect(forwarderActions(forwarding('paused', 'outside'))).toEqual(['resume', 'delete'])
    expect(forwarderActions(forwarding('outdated', 'end_to_end'))).toEqual(['renew', 'delete'])
    expect(forwarderActions(forwarding('rejected', 'outside'))).toEqual(['reinvite', 'delete'])
    expect(forwarderActions(forwarding('rejected', 'end_to_end'))).toEqual(['renew', 'delete'])
  })

  it('lets the forwardee accept or decline a pending one, and delete any other', () => {
    expect(forwardeeActions(forwarding('pending', 'end_to_end'))).toEqual(['accept', 'decline'])
    for (const state of ['active', 'paused', 'outdated'] as const) {
      expect(forwardeeActions(forwarding(state, 'end_to_end'))).toEqual(['delete'])
    }
  })
})

describe('which kind a forwarding is', () => {
  const account = { domain: 'kutup.test', isOwnAddress: (address: string | null | undefined) => address === 'alice@kutup.test' }

  it('is end to end to a person here, outside elsewhere', async () => {
    expect((await forwardingKindOf(account, 'bob@kutup.test')).kind).toBe('end_to_end')
    expect((await forwardingKindOf(account, 'carol@other.test')).kind).toBe('outside')
    expect((await forwardingKindOf(account, 'dave@example.com')).kind).toBe('outside')
  })

  it('never takes an address on this server without a key as outside', async () => {
    await expect(forwardingKindOf(account, 'nobody@kutup.test')).rejects.toEqual(new ForwardeeRefused('unknown'))
    await expect(forwardingKindOf(account, 'nobody@KUTUP.test')).rejects.toEqual(new ForwardeeRefused('unknown'))
  })

  it("refuses the account's own addresses", async () => {
    await expect(forwardingKindOf(account, 'alice@kutup.test')).rejects.toEqual(new ForwardeeRefused('ownAddress'))
  })
})
