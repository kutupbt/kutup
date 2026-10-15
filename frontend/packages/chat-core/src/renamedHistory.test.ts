import { describe, expect, it, vi } from 'vitest'
import type { ChatHistoryEntry } from './types'

vi.mock('@kutup/crypto/accountRename', () => ({
  foldAddress: (address: string) => {
    const at = address.lastIndexOf('@')
    return Promise.resolve(at > 0 ? `${address.slice(0, at).replace(/[._-]/g, '').toLowerCase()}@${address.slice(at + 1).toLowerCase()}` : null)
  },
}))

const { throughRenameAliases } = await import('./renamedHistory')

function entry(id: string, peer: string, direction: 'incoming' | 'outgoing'): ChatHistoryEntry {
  const [username, server] = peer.split('@') as [string, string]
  return {
    id,
    conversation: { kind: 'direct', address: { username, server } },
    sender: direction === 'incoming' ? peer : 'me@kutup.test',
    direction,
    timestampMs: 1,
    delivered: true,
    deduplicated: false,
    content: { version: 1, kind: 'text', sentAt: '', seq: '1', messageId: id, body: null, text: id },
  } as ChatHistoryEntry
}

describe('restored history across a rename', () => {
  it('goes to the thread of the peer’s new address, sender and all', async () => {
    const restored = [entry('a', 'ada_l@kutup.test', 'incoming'), entry('b', 'ada_l@kutup.test', 'outgoing'), entry('c', 'grace@kutup.test', 'incoming')]
    const out = await throughRenameAliases(restored, { 'adal@kutup.test': { to: 'ada_lovelace@kutup.test', incarnationId: 'i', movedAtMs: 0 } })
    expect(out.map((e) => [e.id, e.conversation, e.sender])).toEqual([
      ['a', { kind: 'direct', address: { username: 'ada_lovelace', server: 'kutup.test' } }, 'ada_lovelace@kutup.test'],
      ['b', { kind: 'direct', address: { username: 'ada_lovelace', server: 'kutup.test' } }, 'me@kutup.test'],
      ['c', { kind: 'direct', address: { username: 'grace', server: 'kutup.test' } }, 'grace@kutup.test'],
    ])
  })

  it('keeps what came once someone else took the name under that name', async () => {
    const before = entry('a', 'ada_l@kutup.test', 'incoming')
    const after = { ...entry('b', 'ada_l@kutup.test', 'incoming'), timestampMs: 500 }
    const out = await throughRenameAliases([before, after], {
      'adal@kutup.test': { to: 'ada_lovelace@kutup.test', incarnationId: 'i', movedAtMs: 0, reusedAtMs: 100 },
    })
    expect(out.map((e) => e.sender)).toEqual(['ada_lovelace@kutup.test', 'ada_l@kutup.test'])
  })

  it('leaves everything as it is without aliases', async () => {
    const restored = [entry('a', 'ada_l@kutup.test', 'incoming')]
    expect(await throughRenameAliases(restored, {})).toEqual(restored)
  })
})
