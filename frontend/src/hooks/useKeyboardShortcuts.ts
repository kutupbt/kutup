import { useEffect } from 'react'

export interface ShortcutHandlers {
  onUpload?: () => void
  onNew?: () => void
  onFocusSearch?: () => void
  onClearOrClose?: () => void
  onSelectAll?: () => void
  onDelete?: () => void
  onToggleHelp?: () => void
}

function isTypingTarget(el: EventTarget | null): boolean {
  const node = el as HTMLElement | null
  if (!node) return false
  if (node.isContentEditable) return true
  const tag = node.tagName
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT'
}

export function useKeyboardShortcuts(handlers: ShortcutHandlers) {
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const typing = isTypingTarget(e.target)

      // Esc fires even while typing — used to clear search and blur inputs.
      if (e.key === 'Escape') {
        handlers.onClearOrClose?.()
        return
      }

      if (typing) return

      // ⌘/Ctrl-A → select all visible files. Don't intercept if no handler.
      if ((e.metaKey || e.ctrlKey) && (e.key === 'a' || e.key === 'A')) {
        if (handlers.onSelectAll) {
          e.preventDefault()
          handlers.onSelectAll()
        }
        return
      }

      // No other shortcut uses modifiers
      if (e.metaKey || e.ctrlKey || e.altKey) return

      switch (e.key) {
        case 'u':
        case 'U':
          handlers.onUpload?.()
          e.preventDefault()
          break
        case 'n':
        case 'N':
          handlers.onNew?.()
          e.preventDefault()
          break
        case '/':
          handlers.onFocusSearch?.()
          e.preventDefault()
          break
        case 'Delete':
        case 'Backspace':
          handlers.onDelete?.()
          break
        case '?':
          handlers.onToggleHelp?.()
          e.preventDefault()
          break
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [handlers])
}
