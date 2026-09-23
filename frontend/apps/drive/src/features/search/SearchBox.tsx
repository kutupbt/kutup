import { Search, X } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom'
import { cn } from '@kutup/ui/lib/cn'

const SEARCH_PATH = '/search'

/**
 * The header's search, Google Drive style: typing shows results on
 * /search?q=… as you go; clearing it (✕ or Escape) returns to the page you
 * were on. "/" focuses it from anywhere, as in Drive and GitHub.
 */
export function SearchBox() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const location = useLocation()
  const [params] = useSearchParams()
  const onSearch = location.pathname === SEARCH_PATH
  const [value, setValue] = useState(onSearch ? (params.get('q') ?? '') : '')
  const input = useRef<HTMLInputElement>(null)
  // Where to go back to when the search is cleared.
  const origin = useRef<string>('/')

  // Leaving the results page (opening a folder, the sidebar) empties the box.
  useEffect(() => {
    if (!onSearch) {
      setValue('')
      origin.current = location.pathname + location.search
    }
  }, [onSearch, location.pathname, location.search])

  // Results follow the typing, a beat behind it.
  useEffect(() => {
    const query = value.trim()
    const timer = setTimeout(() => {
      if (query) {
        const next = `${SEARCH_PATH}?${new URLSearchParams({ q: query }).toString()}`
        void navigate(next, { replace: onSearch })
      } else if (onSearch) {
        void navigate(origin.current, { replace: true })
      }
    }, 200)
    return () => clearTimeout(timer)
    // Only typing drives this; navigation state is read, not watched.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value])

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      const target = event.target as HTMLElement
      if (event.key !== '/' || event.ctrlKey || event.metaKey || event.altKey) return
      if (target.closest('input, textarea, [contenteditable="true"], [role="dialog"]')) return
      event.preventDefault()
      input.current?.focus()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return (
    <search className="w-full max-w-2xl">
      <label className="relative flex items-center">
        <span className="sr-only">{t('search.label')}</span>
        <Search className="pointer-events-none absolute left-3.5 size-4 text-muted-foreground" aria-hidden />
        <input
          ref={input}
          type="search"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') {
              setValue('')
              input.current?.blur()
            }
          }}
          placeholder={t('search.placeholder')}
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
            aria-label={t('search.clear')}
            className="absolute right-2 rounded-full p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            <X className="size-4" />
          </button>
        ) : null}
      </label>
    </search>
  )
}
