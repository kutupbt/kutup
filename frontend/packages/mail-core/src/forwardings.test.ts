import { describe, expect, it } from 'vitest'
import { forwardeeActions, forwarderActions, type MailForwarding } from './forwardings'

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
