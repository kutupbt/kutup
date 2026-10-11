import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@kutup/ui/components/dialog'
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
  key: string
  /** When true, only show if showMarkdownShortcuts is on. */
  markdownOnly?: boolean
}

const SHORTCUTS: Shortcut[] = [
  { keys: [MOD, 'S'],         key: 'editor.shortcuts.save' },
  { keys: [MOD, 'F'],         key: 'editor.shortcuts.search' },
  { keys: [MOD, 'Z'],         key: 'editor.shortcuts.undo' },
  { keys: [MOD, 'Shift', 'Z'], key: 'editor.shortcuts.redo' },
  { keys: [MOD, '/'],          key: 'editor.shortcuts.comment' },
  // Markdown-only modes
  { keys: [MOD, 'B'],          key: 'editor.shortcuts.bold', markdownOnly: true },
  { keys: [MOD, 'I'],          key: 'editor.shortcuts.italic', markdownOnly: true },
  { keys: [MOD, 'Shift', 'C'], key: 'editor.shortcuts.code', markdownOnly: true },
  { keys: [MOD, 'K'],          key: 'editor.shortcuts.link', markdownOnly: true },
  { keys: ['[', '['],          key: 'editor.shortcuts.kutupLink', markdownOnly: true },
  { keys: ['Enter'],           key: 'editor.shortcuts.continueList', markdownOnly: true },
  { keys: [MOD, 'P'],          key: 'editor.shortcuts.palette' },
  { keys: [MOD, 'O'],          key: 'editor.shortcuts.switcher' },
  { keys: [MOD, 'Shift', 'F'], key: 'editor.shortcuts.focusMode' },
  { keys: [MOD, 'Shift', '[ / ]'], key: 'editor.shortcuts.fold', markdownOnly: true },
  { keys: [MOD, 'Alt', '[ / ]'], key: 'editor.shortcuts.foldAll', markdownOnly: true },
  { keys: [MOD, 'E'],          key: 'editor.shortcuts.cycleMode', markdownOnly: true },
  { keys: [MOD, 'Shift', 'E'], key: 'editor.shortcuts.cycleModeRev', markdownOnly: true },
  // Multi-cursor / selection
  { keys: ['Alt', 'Click'],    key: 'editor.shortcuts.addCursor' },
  { keys: ['Alt', 'Drag'],     key: 'editor.shortcuts.rectSelect' },
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
          <DialogTitle>{t('editor.shortcuts.title')}</DialogTitle>
          <DialogDescription>
            {t('editor.shortcuts.description')}
          </DialogDescription>
        </DialogHeader>
        <ul className="divide-y divide-border">
          {visible.map((s) => (
            <li key={s.key} className="flex items-center justify-between py-2 text-sm">
              <span>{t(s.key)}</span>
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
