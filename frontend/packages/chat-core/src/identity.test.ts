import { describe, expect, it } from 'vitest'
import {
  addressString,
  contactUri,
  conversationKey,
  directAccount,
  directConversation,
  parseAccount,
  parseAddress,
  parseAddressInput,
} from './identity'

const ALICE = { server: 'example.org', accountId: '00000000-0000-4000-8000-00000000a11c' }

describe('chat identity', () => {
  it('parses only full addresses', () => {
    expect(parseAddress('alice_42')).toBeNull()
    expect(parseAddress('alice_42@Chat.Example')).toEqual({
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
      expect(parseAddress(value), value).toBeNull()
    }
  })

  it('keys a direct chat by the account, never by an address', () => {
    const conversation = directConversation(ALICE)
    expect(conversationKey(conversation)).toBe(`direct:aci:${ALICE.accountId}@example.org`)
    expect(directAccount(conversation)).toEqual(ALICE)
    expect(directAccount({ kind: 'group', groupId: 'g' })).toBeNull()
  })

  it('reads an account key and nothing else', () => {
    expect(parseAccount(`aci:${ALICE.accountId}@example.org`)).toEqual(ALICE)
    expect(parseAccount('alice@example.org')).toBeNull()
    expect(parseAccount(`aci:${ALICE.accountId.toUpperCase()}@example.org`)).toBeNull()
  })

  it('reads a typed bare username as an address on the home server', () => {
    expect(parseAddressInput('alice', 'chat.example')).toEqual({ username: 'alice', server: 'chat.example' })
    expect(parseAddressInput('bob@remote.example', 'chat.example')).toEqual({
      username: 'bob',
      server: 'remote.example',
    })
    expect(parseAddressInput('kutup://contact/bob%40remote.example', 'chat.example')).toEqual({
      username: 'bob',
      server: 'remote.example',
    })
    expect(parseAddressInput('Al', 'chat.example')).toBeNull()
    expect(addressString({ username: 'bob', server: 'remote.example' })).toBe('bob@remote.example')
  })

  it('round-trips a contact link without an alias layer', () => {
    const address = { username: 'alice', server: 'chat.example' }
    const uri = contactUri(address)
    expect(uri).toBe('kutup://contact/alice%40chat.example')
    expect(parseAddress(uri)).toEqual(address)
  })
})
