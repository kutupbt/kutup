import type { ChatHistoryEntry } from './types'

export interface ChatSearchMutationState {
  editedText?: string
  deleted: boolean
}

export interface ChatSearchResult {
  message: ChatHistoryEntry
  preview: string
}

const MAX_CHAT_SEARCH_RESULTS = 100

/**
 * Matches the decrypted history held by this browser (the core's search
 * index proposes candidates; this decides). Every word of the query must
 * begin a word of the message's current text (an edit's, when edited), an
 * attachment's name or caption, or a place's label, folded alike
 * ([`foldSearchText`]). Callers pass the visible history so expired content
 * never enters the result set.
 */
export function searchChatHistory(
  history: ChatHistoryEntry[],
  query: string,
  mutations: ReadonlyMap<string, ChatSearchMutationState>,
  limit = MAX_CHAT_SEARCH_RESULTS,
): ChatSearchResult[] {
  const terms = searchWords(query)
  if (terms.length === 0 || limit <= 0) return []

  return history
    .flatMap(message => {
      const mutation = message.content.messageId
        ? mutations.get(message.content.messageId)
        : undefined
      if (mutation?.deleted) return []

      const effectiveText = mutation?.editedText ?? message.content.text
      const attachment = message.content.attachment
      const searchable = searchableText(message, effectiveText)
      if (!searchable || !matchesWords(searchWords(searchable), terms)) return []

      return [{
        message,
        preview: effectiveText ?? attachment?.caption ?? attachment?.filename ?? '',
      }]
    })
    .sort((left, right) =>
      right.message.timestampMs - left.message.timestampMs
      || right.message.id.localeCompare(left.message.id))
    .slice(0, Math.min(limit, MAX_CHAT_SEARCH_RESULTS))
}

/**
 * What a message can be found by: its text (or `text`, an edit's), an
 * attachment's name and caption, a place's label.
 */
export function searchableText(message: ChatHistoryEntry, text = message.content.text): string {
  const attachment = message.content.attachment
  return [text, attachment?.filename, attachment?.caption, message.content.location?.label]
    .filter((value): value is string => Boolean(value))
    .join('\n')
}

/** Longer words are cut to this many characters, as the core's index does. */
const MAX_WORD_CHARS = 64

/**
 * Folds text for searching, exactly as the core's index does
 * (`kutup-chat-core/src/search.rs`, checked against the shared vectors):
 * Turkish dotted and dotless I to i, accents removed (canonical
 * decomposition, marks dropped), lowercase.
 */
export function foldSearchText(text: string): string {
  const stripped = (value: string) => value.normalize('NFKD').replace(/\p{M}/gu, '')
  return stripped(stripped(text.replace(/[İIı]/gu, 'i')).toLowerCase())
}

/** The distinct folded words of `text`: runs of letters and digits. */
export function searchWords(text: string): string[] {
  const words: string[] = []
  const seen = new Set<string>()
  for (const match of foldSearchText(text).matchAll(/[\p{Alphabetic}\p{N}]+/gu)) {
    const word = Array.from(match[0]).slice(0, MAX_WORD_CHARS).join('')
    if (!seen.has(word)) {
      seen.add(word)
      words.push(word)
    }
  }
  return words
}

/** Every query word begins one of `words`. */
export function matchesWords(words: readonly string[], query: readonly string[]): boolean {
  return query.every(term => words.some(word => word.startsWith(term)))
}
