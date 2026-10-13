import { describe, expect, it } from 'vitest'
import {
  canonicalAccountAddress,
  contactUri,
  conversationKey,
  directConversation,
  parseAccountAddress,
  parseAccountInput,
} from './identity'

describe('canonical chat identity', () => {
  it('parses only full account addresses', () => {
    expect(parseAccountAddress('alice_42')).toBeNull()
    expect(parseAccountAddress('alice_42@Chat.Example')).toEqual({
      username: 'alice_42',
      server: 'chat.example',
    })
  })

  it('does not accept aliases or ambiguous routing forms', () => {
    for (const value of [
      'Alice@example.org',
      'al@example.org',
      'alice@@example.org',
      'alice@example.org.',
      'alice@127.0.0.1',
      'alice@[::1]',
      'alice@example_org',
    ]) {
      expect(parseAccountAddress(value), value).toBeNull()
    }
  })

  it('uses the canonical account as the direct conversation key', () => {
    const address = parseAccountAddress('alice@example.org')!
    expect(canonicalAccountAddress(address)).toBe('alice@example.org')
    expect(conversationKey(directConversation(address))).toBe('direct:alice@example.org')
  })

  it('reads a typed bare username as an account on the home server', () => {
    expect(parseAccountInput('alice', 'chat.example')).toEqual({ username: 'alice', server: 'chat.example' })
    expect(parseAccountInput('bob@remote.example', 'chat.example')).toEqual({
      username: 'bob',
      server: 'remote.example',
    })
    expect(parseAccountInput('kutup://contact/bob%40remote.example', 'chat.example')).toEqual({
      username: 'bob',
      server: 'remote.example',
    })
    expect(parseAccountInput('Al', 'chat.example')).toBeNull()
    expect(canonicalAccountAddress({ username: 'bob', server: 'remote.example' })).toBe(
      'bob@remote.example',
    )
  })

  it('round-trips a canonical QR/contact URI without an alias layer', () => {
    const address = { username: 'alice', server: 'chat.example' }
    const uri = contactUri(address)
    expect(uri).toBe('kutup://contact/alice%40chat.example')
    expect(parseAccountAddress(uri)).toEqual(address)
  })
})
