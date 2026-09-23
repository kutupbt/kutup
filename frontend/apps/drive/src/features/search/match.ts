/**
 * Fold a name or query for matching: case, accents and the Turkish dotted
 * and dotless i all compare equal, so "subat" finds "Şubat" and "ilk" finds
 * "İLK" and "ılık" alike. Names are decrypted in the browser, so this is
 * the whole search: nothing is sent anywhere.
 */
export function fold(value: string): string {
  return value
    .normalize('NFD')
    .replace(/\p{M}/gu, '')
    .replace(/ı/g, 'i')
    .toLowerCase()
}

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
