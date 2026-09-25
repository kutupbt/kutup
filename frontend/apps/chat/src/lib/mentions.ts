import type { ChatMentionV1 } from '@kutup/chat-core/types'

// Mentions as Signal does them: typing "@" in a group offers its members;
// picking one puts "@Name" in the text and remembers who it is. The message
// carries each mention as a range of the text (UTF-16 units, the way
// JavaScript indexes strings) and the member's address, and readers show the
// member's current name there.

/** A member picked in the composer: the text inserted for them, and who. */
export interface MentionPick {
  label: string
  member: string
}

/** The "@query" being typed just before the caret, if any. */
export function mentionQuery(text: string, caret: number): { start: number; query: string } | null {
  const before = text.slice(0, caret)
  const match = /(^|\s)@([^\s@]{0,32})$/u.exec(before)
  if (!match) return null
  const start = caret - match[2].length - 1
  return { start, query: match[2] }
}

/** Replace the "@query" at `start..caret` with the picked label (and a space). */
export function insertMention(
  text: string,
  start: number,
  caret: number,
  label: string,
): { text: string; caret: number } {
  const next = `${text.slice(0, start)}${label} ${text.slice(caret)}`
  return { text: next, caret: start + label.length + 1 }
}

/**
 * The mentions of `text` from the picks made while writing it: each pick's
 * label found in order after the previous one. A pick whose label was edited
 * away is dropped, so a mention never covers text that no longer names them.
 */
export function resolveMentions(text: string, picks: readonly MentionPick[]): ChatMentionV1[] {
  const mentions: ChatMentionV1[] = []
  const used = new Set<number>()
  for (const pick of picks) {
    let from = 0
    for (;;) {
      const at = text.indexOf(pick.label, from)
      if (at < 0) break
      const end = at + pick.label.length
      const free = !mentions.some((m) => at < m.start + m.length && end > m.start)
      // A label must stand alone: not glued to a longer word.
      const boundary = end === text.length || /\s|[.,!?;:)]/u.test(text[end])
      if (free && boundary && !used.has(at)) {
        used.add(at)
        mentions.push({ start: at, length: pick.label.length, member: pick.member })
        break
      }
      from = at + 1
    }
  }
  return mentions.sort((a, b) => a.start - b.start).slice(0, 64)
}

export type MentionPart = { kind: 'text'; value: string } | { kind: 'mention'; member: string; value: string }

/** Split text into plain runs and mentions (ranges that do not fit are ignored). */
export function splitMentions(text: string, mentions: readonly ChatMentionV1[] | undefined): MentionPart[] {
  if (!mentions?.length) return [{ kind: 'text', value: text }]
  const parts: MentionPart[] = []
  let last = 0
  for (const mention of [...mentions].sort((a, b) => a.start - b.start)) {
    const end = mention.start + mention.length
    if (mention.start < last || end > text.length || mention.length < 1) continue
    if (mention.start > last) parts.push({ kind: 'text', value: text.slice(last, mention.start) })
    parts.push({ kind: 'mention', member: mention.member, value: text.slice(mention.start, end) })
    last = end
  }
  if (last < text.length) parts.push({ kind: 'text', value: text.slice(last) })
  return parts
}

/** Whether a message's mentions name `address`. */
export function mentions(list: readonly ChatMentionV1[] | undefined, address: string): boolean {
  return list?.some((mention) => mention.member === address) ?? false
}
