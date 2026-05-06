import { describe, it, expect } from 'vitest'
import { encodeMnemonic, decodeMnemonic, validateMnemonic } from './mnemonic'

// 32-byte fixed entropy → known 24-word BIP39 phrase.
// Verified against bip39: entropy of 32 bytes yields 24 words.
const ENTROPY_ALL_ZEROS = new Uint8Array(32)
const PHRASE_ALL_ZEROS =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ' +
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art'

const ENTROPY_INCREMENTAL = new Uint8Array(32)
for (let i = 0; i < 32; i++) ENTROPY_INCREMENTAL[i] = i

describe('mnemonic — BIP39 24-word', () => {
  it('encodeMnemonic produces 24 words from 32-byte entropy', () => {
    const phrase = encodeMnemonic(ENTROPY_INCREMENTAL)
    expect(phrase.split(/\s+/).length).toBe(24)
  })

  it('rejects non-32-byte entropy', () => {
    expect(() => encodeMnemonic(new Uint8Array(16))).toThrow(/32 bytes/)
    expect(() => encodeMnemonic(new Uint8Array(0))).toThrow(/32 bytes/)
    expect(() => encodeMnemonic(new Uint8Array(33))).toThrow(/32 bytes/)
  })

  it('round-trips entropy through encode → decode', () => {
    const phrase = encodeMnemonic(ENTROPY_INCREMENTAL)
    const recovered = decodeMnemonic(phrase)
    expect(Array.from(recovered)).toEqual(Array.from(ENTROPY_INCREMENTAL))
  })

  it('matches the canonical "abandon × 23 + art" phrase for all-zero entropy', () => {
    expect(encodeMnemonic(ENTROPY_ALL_ZEROS)).toBe(PHRASE_ALL_ZEROS)
    expect(Array.from(decodeMnemonic(PHRASE_ALL_ZEROS))).toEqual(
      Array.from(ENTROPY_ALL_ZEROS),
    )
  })

  it('decodeMnemonic throws on bad-checksum phrase', () => {
    // 24 valid words but checksum is wrong: replace last word with another
    // valid bip39 word that won't satisfy the checksum.
    const bad = PHRASE_ALL_ZEROS.replace(/ art$/, ' zoo')
    expect(() => decodeMnemonic(bad)).toThrow(/Invalid mnemonic/)
  })

  it('decodeMnemonic throws on wrong word count', () => {
    expect(() => decodeMnemonic('abandon abandon abandon')).toThrow(/Invalid mnemonic/)
  })

  it('decodeMnemonic throws on a non-bip39 word', () => {
    const bad = PHRASE_ALL_ZEROS.replace(/^abandon/, 'kutupkutup')
    expect(() => decodeMnemonic(bad)).toThrow(/Invalid mnemonic/)
  })

  it('validateMnemonic returns true for the canonical phrase', () => {
    expect(validateMnemonic(PHRASE_ALL_ZEROS)).toBe(true)
  })

  it('validateMnemonic is case-insensitive and trims whitespace', () => {
    const upper = '  ' + PHRASE_ALL_ZEROS.toUpperCase() + '  '
    expect(validateMnemonic(upper)).toBe(true)
  })

  it('validateMnemonic returns false for bad checksum', () => {
    const bad = PHRASE_ALL_ZEROS.replace(/ art$/, ' zoo')
    expect(validateMnemonic(bad)).toBe(false)
  })

  it('validateMnemonic returns false for empty / garbage input', () => {
    expect(validateMnemonic('')).toBe(false)
    expect(validateMnemonic('not a mnemonic phrase')).toBe(false)
  })
})
