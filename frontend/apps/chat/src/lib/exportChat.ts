import type { TFunction } from 'i18next'
import type { MessageView } from '../state/views'
import { callLogText } from './callText'
import { groupUpdateSentences } from './groupUpdate'
import { messagePreview } from './names'
import { formatCoordinates } from '../features/location/places'

/**
 * A conversation as a plain-text transcript, for keeping outside Kutup:
 * one line per message or notice, "[2026-09-25 14:03] Alice: hello".
 * Attachments appear by name; the file itself is not encrypted.
 */
export function chatTranscript(
  title: string,
  views: readonly MessageView[],
  options: { self: string; nameOf: (address: string) => string; t: TFunction; exportedAt: Date },
): string {
  const { t, nameOf, self } = options
  const lines = [
    t('chat.export.header', { title }),
    t('chat.export.exportedAt', { date: stamp(options.exportedAt) }),
    '',
  ]
  for (const view of views) {
    const at = `[${stamp(new Date(view.entry.timestampMs))}]`
    if (view.groupUpdate) {
      for (const sentence of groupUpdateSentences(view.groupUpdate, self, nameOf, t)) lines.push(`${at} ${sentence}`)
      continue
    }
    if (view.callLog) {
      lines.push(`${at} ${callLogText(view.callLog, t)}`)
      continue
    }
    if (view.undecryptable) {
      lines.push(`${at} ${t(view.undecryptable === 'waiting' ? 'chat.undecryptable.waiting' : 'chat.undecryptable.notice', { name: nameOf(view.author) })}`)
      continue
    }
    if (view.groupCall) {
      lines.push(`${at} ${view.outgoing ? t('chat.calls.groupStarted_you') : t('chat.calls.groupStarted', { name: nameOf(view.author) })}`)
      continue
    }
    if (view.timerChange) {
      lines.push(`${at} ${nameOf(view.author)}: ${t('chat.preview.timer')}`)
      continue
    }
    const attachment = view.entry.content.attachment
    let text = messagePreview(view.entry, view.mutation, t)
    if (attachment && !view.mutation?.deleted && text !== attachment.filename) text = `[${attachment.filename}] ${text}`
    const location = view.entry.content.location
    if (location && !view.mutation?.deleted) text = `${text} (${formatCoordinates(location)})`
    if (view.mutation?.editedText && !view.mutation.deleted) text = `${text} ${t('chat.export.edited')}`
    lines.push(`${at} ${nameOf(view.author)}: ${text}`)
  }
  return `${lines.join('\n')}\n`
}

/** "2026-09-25 14:03" in the local time zone. */
function stamp(date: Date): string {
  const pad = (value: number) => String(value).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`
}

/** A safe file name for the transcript. */
export function transcriptFileName(title: string, now: Date): string {
  const base = title.normalize('NFKD').replace(/\p{M}/gu, '').replace(/[^\p{L}\p{N}]+/gu, '-').replace(/^-|-$/g, '').slice(0, 60) || 'chat'
  const pad = (value: number) => String(value).padStart(2, '0')
  return `kutup-${base}-${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}.txt`
}

/** Hand the transcript to the browser as a download. */
export function downloadText(fileName: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }))
  const link = document.createElement('a')
  link.href = url
  link.download = fileName
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 10_000)
}
