import type { useTranslation } from 'react-i18next'
import type { SettingSection } from '@kutup/session/api-types'
import { windowUnit } from './helpers'
import type { RateLimit } from './RateLimitsPage'

/** Where each section's settings are named in Server settings. */
export const SETTING_LABELS: Record<SettingSection, string> = {
  chatMulti: 'admin.settings.multi',
  calendar: 'admin.settings.calendarLimits',
  chatLinking: 'admin.settings.chatLinkingLimits',
  twoFactor: 'admin.settings.twoFactorLimits',
  drive: 'admin.settings.driveLimits',
  federation: 'admin.settings.federationLimits',
}

type TFunction = ReturnType<typeof useTranslation>['t']

/** What a limit counts, per what and over which window, in words. */
export function countsText(limit: Pick<RateLimit, 'unit' | 'windowSeconds' | 'per'>, t: TFunction): string {
  const per = t(`admin.rateLimits.per.${limit.per}`)
  if ((limit.unit === 'events' || limit.unit === 'bytes') && limit.windowSeconds) {
    const unit = windowUnit(limit.windowSeconds)
    const window = t(`admin.rateLimits.window.${unit.unit}`, { count: unit.count })
    return t(limit.unit === 'bytes' ? 'admin.rateLimits.countsBytes' : 'admin.rateLimits.countsEvents', { per, window })
  }
  if (limit.unit === 'attempts') return t('admin.rateLimits.countsAttempts', { per })
  if (limit.unit === 'atOnce') return t('admin.rateLimits.countsAtOnce', { per })
  if (limit.unit === 'bytesAtOnce') return t('admin.rateLimits.countsBytesAtOnce', { per })
  return t('admin.rateLimits.countsMinutes')
}
