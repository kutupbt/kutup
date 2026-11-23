// Passphrases from the EFF large word list (docs/plans/pass-gaps-3.md, A1),
// as KeePassXC makes them: words picked with the cryptographic random source
// (randomBelow, no modulo bias), joined by a separator. The list is served
// from Kutup's own origin and fetched only when the generator wants it.
// Words: EFF Large Wordlist, Electronic Frontier Foundation, CC BY 3.0
// (https://www.eff.org/dice).

import { randomBelow } from './generator'

/** Where the list is served, beside the app. */
export const WORDLIST_URL = '/wordlists/eff_large.txt'
/** The EFF large list's size: five dice. */
export const WORDLIST_SIZE = 7776
export const MIN_WORDS = 3
export const MAX_WORDS = 20

export type WordCase = 'lower' | 'first' | 'random'

export interface PassphraseOptions {
  words: number
  separator: string
  wordCase: WordCase
  /** A digit after one word, picked at random. */
  addNumber: boolean
  /** A symbol after one word, picked at random. */
  addSymbol: boolean
}

export const DEFAULT_PASSPHRASE: PassphraseOptions = { words: 7, separator: '-', wordCase: 'lower', addNumber: false, addSymbol: false }

const SYMBOLS = '!#$%&*+-.:;=?@^_~'

let loading: Promise<string[]> | null = null

/** Checks a fetched list: the EFF list's size, each word once, lowercase letters and hyphens. */
export function parseWordlist(text: string): string[] {
  const words = text.split('\n').map((w) => w.trim()).filter(Boolean)
  if (words.length !== WORDLIST_SIZE || new Set(words).size !== WORDLIST_SIZE || !words.every((w) => /^[a-z-]+$/.test(w))) {
    throw new Error('the word list is not the EFF large list')
  }
  return words
}

/** The word list, fetched once (a failure is not kept). */
export function loadWordlist(): Promise<string[]> {
  if (!loading) {
    loading = fetch(WORDLIST_URL, { credentials: 'omit' })
      .then((response) => {
        if (!response.ok) throw new Error(`word list: ${response.status}`)
        return response.text()
      })
      .then(parseWordlist)
    loading.catch(() => {
      loading = null
    })
  }
  return loading
}

/** A passphrase of `options.words` words from `wordlist`. */
export function generatePassphrase(wordlist: string[], options: PassphraseOptions): string {
  const count = Math.min(MAX_WORDS, Math.max(MIN_WORDS, options.words))
  const words = Array.from({ length: count }, () => {
    const word = wordlist[randomBelow(wordlist.length)]
    if (options.wordCase === 'first' || (options.wordCase === 'random' && randomBelow(2) === 1)) {
      return word.charAt(0).toUpperCase() + word.slice(1)
    }
    return word
  })
  if (options.addNumber) {
    const at = randomBelow(count)
    words[at] += String(randomBelow(10))
  }
  if (options.addSymbol) {
    const at = randomBelow(count)
    words[at] += SYMBOLS[randomBelow(SYMBOLS.length)]
  }
  return words.join(options.separator)
}

/** Bits of entropy of a passphrase drawn this way. */
export function passphraseBits(options: PassphraseOptions): number {
  const count = Math.min(MAX_WORDS, Math.max(MIN_WORDS, options.words))
  let bits = count * Math.log2(WORDLIST_SIZE)
  if (options.wordCase === 'random') bits += count
  if (options.addNumber) bits += Math.log2(10 * count)
  if (options.addSymbol) bits += Math.log2(SYMBOLS.length * count)
  return Math.floor(bits)
}
