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
      const { key } = securityEventLabel({ kind })
      expect(key).toBe(`settings.security.events.kind.${kind}`)
      expect(typeof lookup(en, key)).toBe('string')
      expect(typeof lookup(tr, key)).toBe('string')
    }
  })

  it('reads a kind it does not know generically', () => {
    for (const kind of ['totpChange', '', 'other.nested', '__proto__']) {
      expect(securityEventLabel({ kind })).toEqual({ key: 'settings.security.events.kind.other' })
    }
    expect(typeof lookup(en, 'settings.security.events.kind.other')).toBe('string')
    expect(typeof lookup(tr, 'settings.security.events.kind.other')).toBe('string')
  })
})

describe('securityEventLabel for names', () => {
  it('names the old and new name of a rename, in both languages', () => {
    const label = securityEventLabel({ kind: 'rename', oldName: 'ada.l', newName: 'ada.lovelace' })
    expect(label).toEqual({
      key: 'settings.security.events.kind.rename',
      values: { oldName: 'ada.l', newName: 'ada.lovelace' },
    })
    for (const messages of [en, tr]) {
      const text = lookup(messages, label.key) as string
      expect(text).toContain('{{oldName}}')
      expect(text).toContain('{{newName}}')
    }
  })

  it('names the held name of a drop, a close and a free', () => {
    for (const kind of ['nameDropped', 'nameClosed', 'nameFreed']) {
      const label = securityEventLabel({ kind, oldName: 'ada.l' })
      expect(label).toEqual({ key: `settings.security.events.kind.${kind}`, values: { oldName: 'ada.l' } })
      for (const messages of [en, tr]) expect(lookup(messages, label.key) as string).toContain('{{oldName}}')
    }
  })

  it('reads a name event without its names generically', () => {
    expect(securityEventLabel({ kind: 'rename', oldName: 'ada.l' })).toEqual({ key: 'settings.security.events.kind.other' })
    expect(securityEventLabel({ kind: 'nameFreed' })).toEqual({ key: 'settings.security.events.kind.other' })
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
