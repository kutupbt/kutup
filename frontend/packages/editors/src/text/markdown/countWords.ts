/** Count words in a string. Splits on whitespace; ignores empty entries.
 *  Markdown markers (#, *, -) are treated as words too — close enough to
 *  the human sense of "how much have I written." */
export function countWords(text: string): number {
  if (!text) return 0
  const matches = text.match(/\S+/g)
  return matches ? matches.length : 0
}
