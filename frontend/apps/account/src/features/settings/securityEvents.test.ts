import { describe, expect, it } from 'vitest'
import en from '../../locales/en.json'
import tr from '../../locales/tr.json'
import { securityEventDevice, securityEventLabel } from './securityEvents'

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

describe('securityEventDevice', () => {
  const firefox = 'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0'

  it('names the device as the session list does', () => {
    expect(securityEventDevice({ client: 'web-account', userAgent: firefox })).toEqual({
      key: 'settings.sessions.browserOn',
      values: { browser: 'Firefox', os: 'Linux' },
    })
    expect(securityEventDevice({ client: 'cli', userAgent: 'kutup-cli/0.1' })).toEqual({ key: 'settings.sessions.cli' })
    expect(securityEventDevice({ client: 'web-pass', userAgent: null })).toEqual({ key: 'settings.sessions.unknownBrowser' })
  })

  it('names none when no session made it (a recovery, an administrator)', () => {
    expect(securityEventDevice({ client: null, userAgent: null })).toBeNull()
  })
})
