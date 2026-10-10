import { fold } from '@kutup/ui/lib/fold'

/**
 * Drive search: names are decrypted in the browser, so matching here is the
 * whole search and nothing is sent anywhere. `fold` makes case, accents and
 * the Turkish i compare equal.
 */
export { fold }

/** The query's words, folded. */
export function terms(query: string): string[] {
  return fold(query).split(/\s+/).filter(Boolean)
}

/** Every word of the query appears somewhere in the name, in any order. */
export function matches(name: string, queryTerms: string[]): boolean {
  if (queryTerms.length === 0) return false
  const folded = fold(name)
  return queryTerms.every((term) => folded.includes(term))
}
