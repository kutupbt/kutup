// A searchable list in a dialog, as Obsidian's command palette and quick
// switcher: type to filter (case, accents and the Turkish i fold), arrows to
// move, Enter to run, Esc to close. Matched letters are highlighted.

import { Search } from 'lucide-react'
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@kutup/ui/components/dialog'
import { cn } from '@kutup/ui/lib/cn'
import { fold } from '@kutup/ui/lib/fold'

export interface PaletteItem {
  id: string
  label: string
  /** Softer text after the label (a folder path, a group). */
  detail?: string
  icon?: ReactNode
  /** Shortcut hint, right-aligned. */
  keys?: string
  run: () => void
}

const MAX_SHOWN = 60

/** Every word of the query somewhere in the label (or detail); a label match ranks first. */
function rank(items: PaletteItem[], query: string): PaletteItem[] {
  const words = fold(query).split(/\s+/).filter(Boolean)
  if (words.length === 0) return items.slice(0, MAX_SHOWN)
  const scored: { item: PaletteItem; score: number }[] = []
  for (const item of items) {
    const label = fold(item.label)
    const all = `${label} ${fold(item.detail ?? '')}`
    if (!words.every((w) => all.includes(w))) continue
    const inLabel = words.every((w) => label.includes(w))
    const prefix = label.startsWith(words[0])
    scored.push({ item, score: (inLabel ? 2 : 0) + (prefix ? 1 : 0) })
  }
  return scored.sort((a, b) => b.score - a.score).slice(0, MAX_SHOWN).map((s) => s.item)
}

/** The label with the query's words marked. */
function Highlighted({ text, query }: { text: string; query: string }) {
  const words = fold(query).split(/\s+/).filter(Boolean)
  if (words.length === 0) return <>{text}</>
  const folded = fold(text)
  // fold keeps lengths for the letters that matter here; fall back to plain text if not.
  if (folded.length !== text.length) return <>{text}</>
  const marked = new Array<boolean>(text.length).fill(false)
  for (const w of words) {
    for (let i = folded.indexOf(w); i >= 0; i = folded.indexOf(w, i + w.length)) {
      for (let j = i; j < i + w.length; j++) marked[j] = true
    }
  }
  const parts: ReactNode[] = []
  let start = 0
  for (let i = 1; i <= text.length; i++) {
    if (i === text.length || marked[i] !== marked[start]) {
      const piece = text.slice(start, i)
      parts.push(marked[start] ? <mark key={start} className="bg-transparent font-semibold text-primary">{piece}</mark> : piece)
      start = i
    }
  }
  return <>{parts}</>
}

export default function CommandPalette({
  open,
  onOpenChange,
  title,
  placeholder,
  empty,
  items,
  loading = false,
  loadingLabel,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** For screen readers (the dialog shows only the search field). */
  title: string
  placeholder: string
  empty: string
  items: PaletteItem[]
  loading?: boolean
  loadingLabel?: string
}) {
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const list = useRef<HTMLUListElement>(null)
  const shown = useMemo(() => rank(items, query), [items, query])

  useEffect(() => {
    if (open) {
      setQuery('')
      setActive(0)
    }
  }, [open])
  useEffect(() => setActive(0), [query])
  useEffect(() => {
    list.current?.querySelector<HTMLElement>(`[data-index="${active}"]`)?.scrollIntoView({ block: 'nearest' })
  }, [active])

  const run = (item: PaletteItem | undefined) => {
    if (!item) return
    onOpenChange(false)
    // After the dialog has handed focus back.
    setTimeout(item.run, 0)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className="top-[12vh] max-w-xl translate-y-0 gap-0 overflow-hidden p-0 [&>button:last-child]:hidden"
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown') {
            e.preventDefault()
            setActive((a) => Math.min(a + 1, shown.length - 1))
          } else if (e.key === 'ArrowUp') {
            e.preventDefault()
            setActive((a) => Math.max(a - 1, 0))
          } else if (e.key === 'Enter') {
            e.preventDefault()
            run(shown[active])
          }
        }}
      >
        <DialogTitle className="sr-only">{title}</DialogTitle>
        <DialogDescription className="sr-only">{placeholder}</DialogDescription>
        <div className="flex items-center gap-2 border-b border-border px-4">
          <Search className="size-4 shrink-0 text-muted-foreground" aria-hidden />
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={placeholder}
            aria-label={placeholder}
            role="combobox"
            aria-expanded="true"
            aria-controls="palette-list"
            aria-activedescendant={shown[active] ? `palette-${shown[active].id}` : undefined}
            className="h-12 w-full bg-transparent text-[15px] outline-none placeholder:text-muted-foreground"
          />
        </div>
        <ul id="palette-list" ref={list} role="listbox" className="max-h-[min(60vh,420px)] overflow-y-auto overscroll-contain p-1.5">
          {shown.length === 0 ? (
            <li className="px-3 py-6 text-center text-sm text-muted-foreground">{loading ? loadingLabel : empty}</li>
          ) : (
            shown.map((item, i) => (
              <li
                key={item.id}
                id={`palette-${item.id}`}
                data-index={i}
                role="option"
                aria-selected={i === active}
                onMouseMove={() => setActive(i)}
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => run(item)}
                className={cn(
                  'flex cursor-pointer items-center gap-3 rounded-md px-3 py-2 text-sm',
                  i === active ? 'bg-accent text-accent-foreground' : 'text-foreground',
                )}
              >
                {item.icon ? <span className="flex size-4 shrink-0 items-center justify-center text-muted-foreground [&_svg]:size-4">{item.icon}</span> : null}
                <span className="min-w-0 flex-1 truncate">
                  <Highlighted text={item.label} query={query} />
                  {item.detail ? <span className="ml-2 text-xs text-muted-foreground">{item.detail}</span> : null}
                </span>
                {item.keys ? <kbd className="shrink-0 rounded border border-border bg-muted px-1.5 py-0.5 font-sans text-[11px] text-muted-foreground">{item.keys}</kbd> : null}
              </li>
            ))
          )}
        </ul>
      </DialogContent>
    </Dialog>
  )
}
