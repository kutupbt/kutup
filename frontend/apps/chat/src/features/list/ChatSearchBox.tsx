import { Search, X } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'
import { cn } from '@kutup/ui/lib/cn'

/**
 * The header's search. As in Signal Desktop, results take the place of the
 * conversation list while there is a query (`?q=`, so the open conversation
 * stays open); clearing it (✕ or Escape) brings the list back. Only the
 * history already decrypted in this browser is searched. Ctrl/⌘+F and "/"
 * focus it.
 */
export function ChatSearchBox() {
  const { t } = useTranslation()
  const [params, setParams] = useSearchParams()
  const [value, setValue] = useState(params.get('q') ?? '')
  const input = useRef<HTMLInputElement>(null)

  // A query cleared elsewhere (opening a result) empties the box.
  const current = params.get('q') ?? ''
  useEffect(() => {
    if (!current) setValue('')
  }, [current])

  useEffect(() => {
    const query = value.trim()
    const timer = setTimeout(() => {
      if (query === (params.get('q') ?? '')) return
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev)
          if (query) next.set('q', query)
          else next.delete('q')
          return next
        },
        { replace: true },
      )
    }, 150)
    return () => clearTimeout(timer)
    // Only typing drives this.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value])

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      const target = event.target as HTMLElement
      const find = (event.ctrlKey || event.metaKey) && !event.shiftKey && event.key.toLowerCase() === 'f'
      const slash = event.key === '/' && !event.ctrlKey && !event.metaKey && !event.altKey
      if (!find && !slash) return
      if (slash && target.closest('input, textarea, [contenteditable="true"]')) return
      if (target.closest('[role="dialog"]')) return
      event.preventDefault()
      input.current?.focus()
      input.current?.select()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return (
    <search className="w-full max-w-2xl">
      <label className="relative flex items-center">
        <span className="sr-only">{t('chat.search.label')}</span>
        <Search className="pointer-events-none absolute left-3.5 size-4 text-muted-foreground" aria-hidden />
        <input
          ref={input}
          type="search"
          data-testid="chat-search-input"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') {
              setValue('')
              input.current?.blur()
            }
          }}
          placeholder={t('chat.search.placeholder')}
          autoComplete="off"
          spellCheck={false}
          className={cn(
            'h-10 w-full rounded-full border border-transparent bg-muted pl-10 pr-10 text-sm outline-none transition-colors',
            'placeholder:text-muted-foreground hover:bg-muted/80',
            'focus:border-ring focus:bg-background focus-visible:ring-2 focus-visible:ring-ring/30',
            '[&::-webkit-search-cancel-button]:hidden',
          )}
        />
        {value ? (
          <button
            type="button"
            onClick={() => {
              setValue('')
              input.current?.focus()
            }}
            aria-label={t('chat.search.clear')}
            className="absolute right-2 rounded-full p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            <X className="size-4" />
          </button>
        ) : null}
      </label>
    </search>
  )
}
