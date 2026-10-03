import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'

const mac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform)
const MOD = mac ? '⌘' : 'Ctrl'
const ALT = mac ? '⌥' : 'Alt'

/** The shortcuts, as the help dialog lists them. */
const SHORTCUTS: Array<{ keys: string[]; label: string }> = [
  { keys: [MOD, 'K'], label: 'search' },
  { keys: [ALT, 'N'], label: 'newChat' },
  { keys: [ALT, '↑'], label: 'previousChat' },
  { keys: [ALT, '↓'], label: 'nextChat' },
  { keys: ['Enter'], label: 'send' },
  { keys: ['Shift', 'Enter'], label: 'newLine' },
  { keys: ['↑'], label: 'editLast' },
  { keys: ['Esc'], label: 'cancel' },
  { keys: [MOD, '/'], label: 'help' },
]

/** Dispatched on `window` to open the shortcut list (Settings has a button). */
const SHOW_SHORTCUTS_EVENT = 'kutup-chat-show-shortcuts'

function inEditable(target: EventTarget | null): boolean {
  return target instanceof HTMLElement && (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName))
}

/**
 * Keyboard shortcuts for the chat, like Signal Desktop's, chosen not to
 * collide with the browser's own (Ctrl+N opens a window, so a new chat is
 * Alt+N). The help dialog lists them.
 */
export function Shortcuts({ onNewChat }: { onNewChat: () => void }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [help, setHelp] = useState(false)

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (document.querySelector('[role="dialog"], [role="alertdialog"]') && !(event.key === '/' && (event.ctrlKey || event.metaKey))) return
      const mod = event.ctrlKey || event.metaKey
      if (mod && !event.altKey && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        document.querySelector<HTMLInputElement>('[data-testid="chat-search-input"]')?.focus()
        return
      }
      if (mod && event.key === '/') {
        event.preventDefault()
        setHelp((open) => !open)
        return
      }
      if (event.altKey && !mod && event.code === 'KeyN') {
        event.preventDefault()
        onNewChat()
        return
      }
      if (event.altKey && !mod && (event.key === 'ArrowUp' || event.key === 'ArrowDown')) {
        // Alt+arrows move between chats even from the message box.
        const links = [...document.querySelectorAll<HTMLAnchorElement>('[data-testid="chat-conversation-list"] a[href^="/c/"]')]
        if (links.length === 0) return
        event.preventDefault()
        const current = links.findIndex((link) => link.getAttribute('aria-current') === 'page')
        const step = event.key === 'ArrowDown' ? 1 : -1
        const next = current < 0 ? (step > 0 ? 0 : links.length - 1) : (current + step + links.length) % links.length
        const href = links[next]?.getAttribute('href')
        if (href) void navigate(href)
        return
      }
      if (!mod && !event.altKey && event.key === '?' && !inEditable(event.target)) {
        event.preventDefault()
        setHelp(true)
      }
    }
    const openHelp = () => setHelp(true)
    window.addEventListener('keydown', onKey)
    window.addEventListener(SHOW_SHORTCUTS_EVENT, openHelp)
    return () => {
      window.removeEventListener('keydown', onKey)
      window.removeEventListener(SHOW_SHORTCUTS_EVENT, openHelp)
    }
  }, [navigate, onNewChat])

  return (
    <Dialog open={help} onOpenChange={setHelp}>
      <DialogContent className="sm:max-w-md" data-testid="chat-shortcuts">
        <DialogHeader>
          <DialogTitle>{t('chat.shortcuts.title')}</DialogTitle>
          <DialogDescription>{t('chat.shortcuts.description')}</DialogDescription>
        </DialogHeader>
        <dl className="space-y-2">
          {SHORTCUTS.map((shortcut) => (
            <div key={shortcut.label} className="flex items-center justify-between gap-4 text-sm">
              <dt>{t(`chat.shortcuts.${shortcut.label}`)}</dt>
              <dd className="flex gap-1">
                {shortcut.keys.map((key) => (
                  <kbd key={key} className="rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-xs">{key}</kbd>
                ))}
              </dd>
            </div>
          ))}
        </dl>
      </DialogContent>
    </Dialog>
  )
}
