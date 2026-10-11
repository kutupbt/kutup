import { useTranslation } from 'react-i18next'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'

const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform)
const META = isMac ? '⌘' : 'Ctrl'

/** Each shortcut: its i18n key under `shortcuts.keys`, and the keys pressed together (alternatives with " / "). */
const SECTIONS: { id: string; shortcuts: [string, string[]][] }[] = [
  {
    id: 'navigation',
    shortcuts: [
      ['next', ['J / ↓']],
      ['previous', ['K / ↑']],
      ['close', ['Esc']],
      ['search', ['/']],
      ['help', ['?']],
    ],
  },
  {
    id: 'selection',
    shortcuts: [
      ['select', ['X']],
      ['extend', ['Shift', '↓ / ↑']],
      ['range', ['Shift', 'Click']],
      ['toggle', [META, 'Click']],
      ['all', [META, 'A']],
      ['menu', ['Right click']],
    ],
  },
  {
    id: 'actions',
    shortcuts: [
      ['new', ['N']],
      ['star', ['*']],
      ['read', ['R']],
      ['unread', ['U']],
      ['inbox', ['I']],
      ['archive', ['A']],
      ['spam', ['S']],
      ['trash', ['T / Delete']],
      ['moveTo', ['M']],
      ['labelAs', ['L']],
      ['deleteForever', [META, 'Backspace']],
      ['drag', ['Drag']],
    ],
  },
  {
    id: 'composer',
    shortcuts: [
      ['send', [META, 'Enter']],
      ['closeComposer', ['Esc']],
    ],
  },
]

/** The list of keyboard shortcuts, as Proton's "?" shows them. */
export function ShortcutsDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation()
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{t('shortcuts.title')}</DialogTitle>
        </DialogHeader>
        <div className="grid gap-6 sm:grid-cols-2">
          {SECTIONS.map((section) => (
            <section key={section.id} aria-labelledby={`shortcuts-${section.id}`}>
              <h3 id={`shortcuts-${section.id}`} className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                {t(`shortcuts.sections.${section.id}`)}
              </h3>
              <dl className="space-y-1.5 text-sm">
                {section.shortcuts.map(([id, combo]) => (
                  <div key={id} className="flex items-center justify-between gap-3">
                    <dt>{t(`shortcuts.keys.${id}`)}</dt>
                    <dd className="flex shrink-0 items-center gap-1">
                      {combo.map((key, i) => (
                        <span key={key} className="flex items-center gap-1">
                          {i > 0 ? <span className="text-muted-foreground">+</span> : null}
                          <kbd className="rounded border border-border bg-muted px-1.5 py-0.5 font-sans text-xs">
                            {key === 'Click' || key === 'Right click' || key === 'Drag' ? t(`shortcuts.mouse.${key === 'Right click' ? 'rightClick' : key.toLowerCase()}`) : key}
                          </kbd>
                        </span>
                      ))}
                    </dd>
                  </div>
                ))}
              </dl>
            </section>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  )
}
