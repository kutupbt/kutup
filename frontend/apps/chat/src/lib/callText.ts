import type { TFunction } from 'i18next'
import type { ChatCallLog } from '@kutup/chat-core/types'

/** "3:07", or "1:02:03" past an hour. */
export function formatDuration(seconds: number): string {
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  const rest = String(seconds % 60).padStart(2, '0')
  return hours > 0 ? `${hours}:${String(minutes).padStart(2, '0')}:${rest}` : `${minutes}:${rest}`
}

/** One call in the timeline: "Missed voice call", "Outgoing video call · 3:07". */
export function callLogText(log: ChatCallLog, t: TFunction): string {
  const call = t(log.media === 'video' ? 'chat.calls.videoCall' : 'chat.calls.voiceCall')
  const direction = log.incoming ? 'In' : 'Out'
  const key = log.outcome === 'missed' || log.outcome === 'unanswered' || log.outcome === 'busy' || log.outcome === 'failed'
    ? `chat.calls.log.${log.outcome}`
    : `chat.calls.log.${log.outcome}${direction}`
  const text = t(key, { call })
  return log.outcome === 'answered' && log.durationSeconds !== undefined
    ? `${text} · ${formatDuration(log.durationSeconds)}`
    : text
}
