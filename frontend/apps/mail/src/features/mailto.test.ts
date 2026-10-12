import { describe, expect, it } from 'vitest'
import { parseMailto } from './mailto'

describe('mailto links', () => {
  it('reads to, cc, bcc, subject and body', () => {
    const m = parseMailto('mailto:ali@example.org,ayse@example.org?cc=can@example.org&bcc=gizli@example.org&subject=Merhaba%20d%C3%BCnya&body=Sat%C4%B1r%201%0ASat%C4%B1r%202')!
    expect(m.to.map((x) => x.address)).toEqual(['ali@example.org', 'ayse@example.org'])
    expect(m.cc.map((x) => x.address)).toEqual(['can@example.org'])
    expect(m.bcc.map((x) => x.address)).toEqual(['gizli@example.org'])
    expect(m.subject).toBe('Merhaba dünya')
    expect(m.body).toBe('Satır 1\nSatır 2')
  })

  it('takes a link the browser encoded once, and refuses others', () => {
    expect(parseMailto('mailto%3Aali%40example.org%3Fsubject%3DHi')!.to[0].address).toBe('ali@example.org')
    expect(parseMailto('https://example.org')).toBeNull()
    expect(parseMailto('mailto:?subject=Only')!.to).toEqual([])
  })
})
