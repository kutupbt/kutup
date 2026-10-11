import { describe, expect, it } from 'vitest'
import { leadsOutside, shownUrl } from './links'

describe('links in messages', () => {
  it('lead outside unless they stay on Kutup’s own sites', () => {
    expect(leadsOutside('https://example.org/x', 'mail.kutup.dev')).toBe(true)
    expect(leadsOutside('https://drive.kutup.dev/f/1', 'mail.kutup.dev')).toBe(false)
    expect(leadsOutside('https://kutup.dev/', 'mail.kutup.dev')).toBe(false)
    expect(leadsOutside('https://kutup.dev.evil.example/', 'mail.kutup.dev')).toBe(true)
    expect(leadsOutside('mailto:a@b.c', 'mail.kutup.dev')).toBe(false)
    expect(leadsOutside('javascript:alert(1)', 'mail.kutup.dev')).toBe(false)
  })

  it('show where they really go: punycode hosts, no bidi controls', () => {
    expect(shownUrl('https://аpple.com/')).toBe('https://xn--pple-43d.com/')
    expect(shownUrl('https://example.org/‮gnp.exe')).toBe('https://example.org/%E2%80%AEgnp.exe')
    expect(shownUrl('not a url ‮')).toBe('not a url ')
  })
})
