import { describe, expect, it } from 'vitest'
import { iconDomain } from './siteIcons'

describe('iconDomain', () => {
  it('sends only the host name of an entry address', () => {
    expect(iconDomain('https://accounts.example.org/login?next=/inbox#x')).toBe('accounts.example.org')
    expect(iconDomain('http://Example.ORG.')).toBe('example.org')
    expect(iconDomain('example.org/signin')).toBe('example.org')
    expect(iconDomain('  github.com ')).toBe('github.com')
    expect(iconDomain('https://user:pw@bank.example/')).toBe('bank.example')
    expect(iconDomain('https://bücher.example/')).toBe('xn--bcher-kva.example')
  })

  it('has none for addresses without a public name', () => {
    for (const address of ['', 'intranet', 'localhost:8080', 'https://app.localhost/', 'https://192.168.1.1/', '10.0.0.1', 'https://[::1]/', 'ssh://example.org', 'mailto:a@example.org', 'cmd://putty']) {
      expect(iconDomain(address), address).toBeNull()
    }
  })
})
