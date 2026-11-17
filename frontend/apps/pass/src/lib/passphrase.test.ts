import { describe, expect, it } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { characterSets, DEFAULT_OPTIONS, entropyBits, generatePassword, MAX_LENGTH } from './generator'
import { DEFAULT_PASSPHRASE, generatePassphrase, parseWordlist, passphraseBits, WORDLIST_SIZE } from './passphrase'

// The file the app serves (vitest runs from frontend/ or from the app).
const servedPath = ['apps/pass/public/wordlists/eff_large.txt', 'public/wordlists/eff_large.txt'].map((p) => resolve(process.cwd(), p)).find((p) => existsSync(p))
const served = readFileSync(servedPath ?? 'missing: apps/pass/public/wordlists/eff_large.txt', 'utf8')

describe('passphrases', () => {
  it('serves the whole EFF large list, each word once', () => {
    const words = parseWordlist(served)
    expect(words).toHaveLength(WORDLIST_SIZE)
    expect(words[0]).toBe('abacus')
    expect(words[WORDLIST_SIZE - 1]).toBe('zoom')
  })

  it('refuses a list that is not the EFF list', () => {
    expect(() => parseWordlist('a\nb\n')).toThrow()
    expect(() => parseWordlist(served.replace('abacus', 'Abacus'))).toThrow()
  })

  it('joins the asked number of list words, cased and with extras as asked', () => {
    const words = parseWordlist(served)
    const known = new Set(words)
    const plain = generatePassphrase(words, DEFAULT_PASSPHRASE).split('-')
    expect(plain).toHaveLength(7)
    expect(plain.every((w) => known.has(w))).toBe(true)
    const capital = generatePassphrase(words, { ...DEFAULT_PASSPHRASE, words: 4, separator: ' ', wordCase: 'first' }).split(' ')
    expect(capital).toHaveLength(4)
    expect(capital.every((w) => /^[A-Z]/.test(w) && known.has(w.toLowerCase()))).toBe(true)
    // A space between the words, so the added symbol (it may be "-") stands out.
    for (let i = 0; i < 50; i++) {
      const extras = generatePassphrase(words, { ...DEFAULT_PASSPHRASE, words: 3, separator: ' ', addNumber: true, addSymbol: true })
      expect(extras).toMatch(/[0-9]/)
      expect(extras).toMatch(/[!#$%&*+\-.:;=?@^_~]/)
    }
    expect(passphraseBits(DEFAULT_PASSPHRASE)).toBe(90)
  })
})

describe('password character options', () => {
  it('adds custom characters as their own set and never uses excluded ones', () => {
    const options = { ...DEFAULT_OPTIONS, upper: false, digits: false, symbols: false, custom: 'çğ ş', exclude: 'aeiou' }
    const sets = characterSets(options)
    expect(sets).toHaveLength(2)
    expect(sets[1]).toEqual(['ç', 'ğ', 'ş'])
    for (let i = 0; i < 50; i++) {
      const value = generatePassword({ ...options, length: 12 })
      expect(value).not.toMatch(/[aeiou]/)
      expect(value).toMatch(/[çğş]/)
    }
  })

  it('caps the length and counts the sets for the strength', () => {
    expect([...generatePassword({ ...DEFAULT_OPTIONS, length: 500 })]).toHaveLength(MAX_LENGTH)
    expect(characterSets({ ...DEFAULT_OPTIONS, lower: false, upper: false, digits: false, symbols: false })).toEqual([])
    expect(entropyBits({ ...DEFAULT_OPTIONS, lower: false, upper: false, symbols: false, length: 10 })).toBe(33)
  })
})
