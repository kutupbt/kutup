import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { isShortcutKey, setShortcutsEnabled, useShortcutsEnabled } from '@kutup/session/shortcuts'
import { ShortcutsDialog, type ShortcutSection } from '@kutup/ui/components/shortcuts-dialog'
import { openShortcuts, useShortcutsOpen } from './shortcutsState'

// Drive's keys (docs/roadmap.md, "Keyboard shortcuts in every app"): Proton
// Drive has no shortcut set, so this lists the keys the file list already
// takes. Moving and selecting in the list always work (as any list's keys);
// the account's switch turns off `/` and `?`.

const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform)
const META = isMac ? '⌘' : 'Ctrl'

export function DriveShortcuts() {
  const { t } = useTranslation()
  const isOpen = useShortcutsOpen()
  const enabled = useShortcutsEnabled()
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== '?' || !isShortcutKey(event)) return
      event.preventDefault()
      openShortcuts()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])
  const sections: ShortcutSection[] = [
    {
      name: t('keys.basic'),
      shortcuts: [
        { name: t('keys.search'), keys: ['/'] },
        { name: t('keys.help'), keys: ['?'] },
      ],
    },
    {
      name: t('keys.list'),
      shortcuts: [
        { name: t('keys.move'), keys: ['↑', '↓'] },
        { name: t('keys.firstLast'), keys: ['Home', 'End'] },
        { name: t('keys.open'), keys: ['Enter'] },
        { name: t('keys.quickLook'), keys: ['Space'] },
        { name: t('keys.extend'), keys: ['Shift + ↑', 'Shift + ↓'] },
        { name: t('keys.all'), keys: [`${META} + A`] },
        { name: t('keys.clear'), keys: ['Esc'] },
        { name: t('keys.trash'), keys: ['Delete', 'Backspace'] },
      ],
    },
  ]
  return <ShortcutsDialog open={isOpen} onOpenChange={openShortcuts} sections={sections} enabled={enabled} onEnabledChange={setShortcutsEnabled} />
}
