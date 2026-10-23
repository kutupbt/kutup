import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { timeZones } from '@kutup/crypto/calendar'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Label } from '@kutup/ui/components/label'
import { Choice } from './Choice'
import { formatWeekday, zoneOptions } from './format'
import { setPrefs, useCalendarPrefs } from './prefs'
import { NotificationSettings } from './reminders/NotificationSettings'

/** A Sunday, a Monday … a Saturday, to name the weekdays by. */
const WEEK = ['2026-10-25', '2026-10-26', '2026-10-27', '2026-10-28', '2026-10-29', '2026-10-30', '2026-10-31'] as const

/** How this browser shows calendars: the zone, the week's first day, the clock. */
export function SettingsDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t, i18n } = useTranslation()
  const prefs = useCalendarPrefs()
  const zones = useQuery({ queryKey: ['calendar', 'zones'], queryFn: timeZones, staleTime: Infinity, enabled: open })
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('settings.title')}</DialogTitle>
          <DialogDescription>{t('settings.description')}</DialogDescription>
        </DialogHeader>
        <div className="mt-4 space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="settings-zone">{t('settings.zone')}</Label>
            <Choice id="settings-zone" value={prefs.zone} options={zoneOptions(zones.data, prefs.zone)} onChange={(zone) => setPrefs({ zone })} testId="settings-zone" />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="settings-week">{t('settings.weekStart')}</Label>
            <Choice
              id="settings-week"
              value={String(prefs.weekStart)}
              options={[1, 6, 0].map((day) => ({ value: String(day), label: formatWeekday(WEEK[day], i18n.language, 'long') }))}
              onChange={(day) => setPrefs({ weekStart: Number(day) })}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="settings-clock">{t('settings.clock')}</Label>
            <Choice
              id="settings-clock"
              value={prefs.hour12 === null ? 'auto' : prefs.hour12 ? '12' : '24'}
              options={[
                { value: 'auto', label: t('settings.clockAuto') },
                { value: '24', label: t('settings.clock24') },
                { value: '12', label: t('settings.clock12') },
              ]}
              onChange={(clock) => setPrefs({ hour12: clock === 'auto' ? null : clock === '12' })}
            />
          </div>
          <p className="text-xs text-muted-foreground">{t('settings.thisDevice')}</p>
          <NotificationSettings />
        </div>
      </DialogContent>
    </Dialog>
  )
}
