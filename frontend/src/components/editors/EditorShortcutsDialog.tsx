import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog'
import { useTranslation } from 'react-i18next'

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Whether to show the markdown-only shortcuts (Cmd+E etc). */
  showMarkdownShortcuts: boolean
}

// Modifier-key glyph: ⌘ on Mac, Ctrl elsewhere. Matches what most editors
// show in their menus.
const MOD =
  typeof navigator !== 'undefined' && /Mac|iPhone|iPad|iPod/i.test(navigator.platform)
    ? '⌘'
    : 'Ctrl'

interface Shortcut {
  keys: string[]
  labelKey: string
  defaultLabel: string
  /** When true, only show if showMarkdownShortcuts is on. */
  markdownOnly?: boolean
}

const SHORTCUTS: Shortcut[] = [
  { keys: [MOD, 'S'],         labelKey: 'editor.shortcuts.save',         defaultLabel: 'Save' },
  { keys: [MOD, 'F'],         labelKey: 'editor.shortcuts.search',       defaultLabel: 'Find in document' },
  { keys: [MOD, 'Z'],         labelKey: 'editor.shortcuts.undo',         defaultLabel: 'Undo' },
  { keys: [MOD, 'Shift', 'Z'], labelKey: 'editor.shortcuts.redo',         defaultLabel: 'Redo' },
  { keys: [MOD, '/'],          labelKey: 'editor.shortcuts.comment',      defaultLabel: 'Toggle line comment' },
  // Markdown-only modes
  { keys: [MOD, 'E'],          labelKey: 'editor.shortcuts.cycleMode',    defaultLabel: 'Cycle Edit / Split / Read', markdownOnly: true },
  { keys: [MOD, 'Shift', 'E'], labelKey: 'editor.shortcuts.cycleModeRev', defaultLabel: 'Cycle modes backward', markdownOnly: true },
  // Multi-cursor / selection
  { keys: ['Alt', 'Click'],    labelKey: 'editor.shortcuts.addCursor',    defaultLabel: 'Add cursor at click position' },
  { keys: ['Alt', 'Drag'],     labelKey: 'editor.shortcuts.rectSelect',   defaultLabel: 'Rectangular selection' },
]

function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="inline-flex h-6 min-w-[1.5rem] items-center justify-center rounded border bg-muted px-1.5 font-mono text-xs text-foreground shadow-sm">
      {children}
    </kbd>
  )
}

export default function EditorShortcutsDialog({ open, onOpenChange, showMarkdownShortcuts }: Props) {
  const { t } = useTranslation()
  const visible = SHORTCUTS.filter((s) => !s.markdownOnly || showMarkdownShortcuts)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('editor.shortcuts.title', { defaultValue: 'Editor keyboard shortcuts' })}</DialogTitle>
          <DialogDescription>
            {t('editor.shortcuts.desc', {
              defaultValue: 'Available while editing. Search and save are page-wide; the rest fire only when the editor has focus.',
            })}
          </DialogDescription>
        </DialogHeader>
        <ul className="divide-y divide-border">
          {visible.map((s) => (
            <li key={s.defaultLabel} className="flex items-center justify-between py-2 text-sm">
              <span>{t(s.labelKey, { defaultValue: s.defaultLabel })}</span>
              <span className="flex items-center gap-1">
                {s.keys.map((k, i) => (
                  <span key={i} className="flex items-center gap-1">
                    {i > 0 && <span className="text-muted-foreground">+</span>}
                    <Kbd>{k}</Kbd>
                  </span>
                ))}
              </span>
            </li>
          ))}
        </ul>
      </DialogContent>
    </Dialog>
  )
}
