import { describe, expect, it, vi } from 'vitest'

vi.mock('@kutup/chat-core/wasm', () => ({ loadChatWasm: vi.fn() }))
vi.mock('@kutup/session/client', () => ({ default: {} }))
vi.mock('@kutup/crypto', () => ({ toBase64: vi.fn() }))

const { callLinkFragmentOf } = await import('./callLinks')

describe('callLinkFragmentOf', () => {
  const fragment = 'A'.repeat(43) + '_'
  it('takes a whole link or the fragment alone', () => {
    expect(callLinkFragmentOf(`https://chat.example.org/call#${fragment}`)).toBe(fragment)
    expect(callLinkFragmentOf(`  ${fragment}\n`)).toBe(fragment)
  })

  it('refuses what is not a call link', () => {
    expect(callLinkFragmentOf('https://chat.example.org/call')).toBeNull()
    expect(callLinkFragmentOf(`https://chat.example.org/call#${fragment}x`)).toBeNull()
    expect(callLinkFragmentOf(`https://chat.example.org/call#${fragment.slice(1)}`)).toBeNull()
    expect(callLinkFragmentOf(`https://chat.example.org/call#${'+'.repeat(44)}`)).toBeNull()
    expect(callLinkFragmentOf('')).toBeNull()
  })
})
