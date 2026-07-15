import { describe, expect, it } from 'vitest'
import { isSupportedChat } from './capabilities'
import type { ChatCapabilities } from './types'

const supported: ChatCapabilities = {
  enabled: true,
  protocolVersion: 1,
  suites: [1],
  maxContentBytes: 65_536,
  mailboxRetentionDays: 30,
  deviceExpiryDays: 90,
  federation: false,
  manifests: true,
  sealedSender: false,
}

describe('isSupportedChat', () => {
  it('requires the frozen protocol, PQ suite, and signed manifests', () => {
    expect(isSupportedChat(supported)).toBe(true)
    expect(isSupportedChat({ ...supported, enabled: false })).toBe(false)
    expect(isSupportedChat({ ...supported, protocolVersion: 2 })).toBe(false)
    expect(isSupportedChat({ ...supported, suites: [] })).toBe(false)
    expect(isSupportedChat({ ...supported, manifests: false })).toBe(false)
    expect(isSupportedChat(undefined)).toBe(false)
  })
})
