import { describe, expect, it } from 'vitest'
import en from '../../locales/en.json'
import tr from '../../locales/tr.json'
import { securityEventLabel } from './securityEvents'

function lookup(messages: unknown, key: string): unknown {
  return key.split('.').reduce<unknown>((node, part) => (node as Record<string, unknown> | undefined)?.[part], messages)
}

describe('securityEventLabel', () => {
  it('names each known kind, in both languages', () => {
    for (const kind of ['passwordChange', 'recovery', 'rotate', 'adminReset', 'accountReset']) {
      const key = securityEventLabel({ kind })
      expect(key).toBe(`settings.security.events.kind.${kind}`)
      expect(typeof lookup(en, key)).toBe('string')
      expect(typeof lookup(tr, key)).toBe('string')
    }
  })

  it('reads a kind it does not know generically', () => {
    for (const kind of ['totpChange', '', 'other.nested', '__proto__']) {
      expect(securityEventLabel({ kind })).toBe('settings.security.events.kind.other')
    }
    expect(typeof lookup(en, 'settings.security.events.kind.other')).toBe('string')
    expect(typeof lookup(tr, 'settings.security.events.kind.other')).toBe('string')
  })
})
