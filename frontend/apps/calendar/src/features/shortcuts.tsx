import { useTranslation } from 'react-i18next'
import { setShortcutsEnabled, useShortcutsEnabled } from '@kutup/session/shortcuts'
import { ShortcutsDialog, type ShortcutSection } from '@kutup/ui/components/shortcuts-dialog'
import { openShortcuts, useShortcutsOpen } from './shortcutsState'

// Calendar's keyboard shortcuts (Proton's `getShortcuts`, plus D W M for the
// views); `?` and Settings open the list.

export function CalendarShortcuts() {
  const { t } = useTranslation()
  const isOpen = useShortcutsOpen()
  const enabled = useShortcutsEnabled()
  const sections: ShortcutSection[] = [
    {
      name: t('keys.basic'),
      shortcuts: [
        { name: t('keys.newEvent'), keys: ['N'] },
        { name: t('keys.help'), keys: ['?'] },
      ],
    },
    {
      name: t('keys.views'),
      shortcuts: [
        { name: t('keys.today'), keys: ['T'] },
        { name: t('keys.day'), keys: ['D', '1'] },
        { name: t('keys.week'), keys: ['W', '2'] },
        { name: t('keys.month'), keys: ['M', '3'] },
        { name: t('keys.next'), keys: ['→'] },
        { name: t('keys.previous'), keys: ['←'] },
      ],
    },
  ]
  return <ShortcutsDialog open={isOpen} onOpenChange={openShortcuts} sections={sections} enabled={enabled} onEnabledChange={setShortcutsEnabled} />
}
