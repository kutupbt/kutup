import { describe, expect, it } from 'vitest'
import { fold, matches, terms } from './search'

describe('search matching', () => {
  it('ignores case and accents', () => {
    expect(matches('16 Şubat 2021 Toplantı', terms('subat'))).toBe(true)
    expect(matches('Résumé.pdf', terms('resume'))).toBe(true)
  })

  it('treats the Turkish i forms as one letter', () => {
    expect(fold('İLK')).toBe('ilk')
    expect(fold('ılık')).toBe('ilik')
    expect(matches('YÖNETİM KURULU', terms('yonetim'))).toBe(true)
    expect(matches('Toplantı notları', terms('toplanti'))).toBe(true)
  })

  it('needs every word, in any order', () => {
    expect(matches('2022-2023 Finansal Rapor', terms('rapor 2023'))).toBe(true)
    expect(matches('2022-2023 Finansal Rapor', terms('rapor 2024'))).toBe(false)
  })

  it('matches nothing for an empty query', () => {
    expect(matches('anything', terms('   '))).toBe(false)
  })
})
