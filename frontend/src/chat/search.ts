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
 * Search only the decrypted history already held by this browser. Callers pass
 * the visible history so expired content never enters the result set.
 */
export function searchChatHistory(
  history: ChatHistoryEntry[],
  query: string,
  mutations: ReadonlyMap<string, ChatSearchMutationState>,
  limit = MAX_CHAT_SEARCH_RESULTS,
): ChatSearchResult[] {
  const terms = normalizeSearchText(query).split(/\s+/u).filter(Boolean)
  if (terms.length === 0 || limit <= 0) return []

  return history
    .flatMap(message => {
      const mutation = message.content.messageId
        ? mutations.get(message.content.messageId)
        : undefined
      if (mutation?.deleted) return []

      const effectiveText = mutation?.editedText ?? message.content.text
      const attachment = message.content.attachment
      const searchable = [effectiveText, attachment?.filename, attachment?.caption]
        .filter((value): value is string => Boolean(value))
        .join('\n')
      if (!searchable) return []
      const normalized = normalizeSearchText(searchable)
      if (!terms.every(term => normalized.includes(term))) return []

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

function normalizeSearchText(value: string): string {
  return value.normalize('NFKC').toLocaleLowerCase().trim()
}
