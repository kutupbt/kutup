import { describe, expect, it } from 'vitest'
import { isSupportedChat } from './capabilities'
import { DIRECT_CHAT_SUITE, isDirectChatSuiteId } from './suites'
import type { ChatCapabilities } from './types'

const supported: ChatCapabilities = {
  enabled: true,
  protocolVersion: 1,
  suites: [DIRECT_CHAT_SUITE.PqxdhTripleRatchetV1],
  maxContentBytes: 65_536,
  mailboxRetentionDays: 30,
  deviceExpiryDays: 90,
  serverName: 'chat.example',
  federation: false,
  manifests: true,
  profiles: true,
  keyTransparency: true,
  transparencyOperatorKeyId: '11'.repeat(32),
  transparencyOperatorPublicKey: 'MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=',
  transparencyWitnesses: [],
  transparencyWitnessQuorum: 0,
  sealedSender: false,
}

describe('isSupportedChat', () => {
  it('recognizes only implemented Direct Chat suite identifiers', () => {
    expect(isDirectChatSuiteId(1)).toBe(true)
    expect(isDirectChatSuiteId(0)).toBe(false)
    expect(isDirectChatSuiteId(2)).toBe(false)
    expect(isDirectChatSuiteId(-1)).toBe(false)
    expect(isDirectChatSuiteId(1.5)).toBe(false)
    expect(isDirectChatSuiteId('1')).toBe(false)
    expect(isDirectChatSuiteId(undefined)).toBe(false)
  })

  it('requires the frozen protocol, PQ suite, and signed manifests', () => {
    expect(isSupportedChat(supported)).toBe(true)
    expect(isSupportedChat({ ...supported, enabled: false })).toBe(false)
    expect(isSupportedChat({ ...supported, protocolVersion: 2 })).toBe(false)
    expect(isSupportedChat({ ...supported, suites: [] })).toBe(false)
    expect(isSupportedChat({ ...supported, suites: [2] })).toBe(false)
    expect(isSupportedChat({ ...supported, suites: [-1] })).toBe(false)
    expect(isSupportedChat({ ...supported, suites: [1.5] })).toBe(false)
    expect(
      isSupportedChat({
        ...supported,
        suites: ['1'] as unknown as number[],
      }),
    ).toBe(false)
    expect(isSupportedChat({ ...supported, suites: [1, 2] })).toBe(true)
    expect(isSupportedChat({ ...supported, manifests: false })).toBe(false)
    expect(isSupportedChat({ ...supported, profiles: false })).toBe(false)
    expect(isSupportedChat({ ...supported, keyTransparency: false })).toBe(false)
    expect(isSupportedChat({ ...supported, transparencyOperatorKeyId: undefined })).toBe(false)
    expect(
      isSupportedChat({ ...supported, transparencyWitnessQuorum: 1 }),
    ).toBe(false)
    expect(isSupportedChat({ ...supported, federation: true, serverName: undefined })).toBe(false)
    expect(
      isSupportedChat({ ...supported, federation: true, serverName: 'chat.example' }),
    ).toBe(true)
    expect(
      isSupportedChat({ ...supported, federation: true, serverName: 'Chat.Example' }),
    ).toBe(false)
    expect(
      isSupportedChat({ ...supported, federation: true, serverName: '127.0.0.1' }),
    ).toBe(false)
    expect(isSupportedChat(undefined)).toBe(false)
  })
})
