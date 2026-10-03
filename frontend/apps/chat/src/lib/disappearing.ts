import type { TFunction } from 'i18next'
import { formatRemainingTime } from '@kutup/chat-core/disappearing'

/** The disappearing-message times offered (seconds; off is undefined). */
export const DISAPPEARING_PRESETS = [
  { id: 'off', seconds: undefined },
  { id: 'thirtySeconds', seconds: 30 },
  { id: 'oneHour', seconds: 60 * 60 },
  { id: 'oneDay', seconds: 24 * 60 * 60 },
  { id: 'oneWeek', seconds: 7 * 24 * 60 * 60 },
  { id: 'thirtyDays', seconds: 30 * 24 * 60 * 60 },
] as const

/** A timer's length in words ("1 hour"), or its closest short form. */
export function disappearingLabel(seconds: number, t: TFunction): string {
  const preset = DISAPPEARING_PRESETS.find((option) => option.seconds === seconds)
  return preset ? t(`chat.disappearing.presets.${preset.id}`) : formatRemainingTime(seconds * 1_000)
}
