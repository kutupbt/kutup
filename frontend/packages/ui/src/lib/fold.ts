/**
 * Fold text for matching: case, accents and the Turkish dotted and dotless i
 * all compare equal, so "subat" finds "Şubat" and "ilk" finds "İLK" and
 * "ılık" alike.
 */
export function fold(value: string): string {
  return value
    .normalize('NFD')
    .replace(/\p{M}/gu, '')
    .replace(/ı/g, 'i')
    .toLowerCase()
}
