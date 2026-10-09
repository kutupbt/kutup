import { forwardRef, useEffect, useId, useState, type InputHTMLAttributes } from 'react'
import { useTranslation } from 'react-i18next'
import { Input } from '@kutup/ui/components/input'
import { cn } from '@kutup/ui/lib/cn'
import { useContactEmailSearch, type ContactEmailMatch } from '../search'

type Props = Omit<InputHTMLAttributes<HTMLInputElement>, 'value' | 'onChange'> & {
  value: string
  onValueChange: (value: string) => void
  /** Called when a suggestion is picked (the value is already set). */
  onPick?: (match: ContactEmailMatch) => void
}

/** The text before suggestions are asked for: a moment's pause, and two letters. */
function useSettled(value: string, ms = 150) {
  const [settled, setSettled] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setSettled(value), ms)
    return () => clearTimeout(timer)
  }, [value, ms])
  return settled
}

/**
 * An address field that suggests people from the account's contacts as you
 * type (docs/plans/contacts.md): name and address, recently used first,
 * from the server's readable index of contact emails. A combobox: arrows move,
 * Enter picks, Escape closes; typing anything else still works.
 */
export const ContactSuggestInput = forwardRef<HTMLInputElement, Props>(function ContactSuggestInput(
  { value, onValueChange, onPick, className, onKeyDown, onBlur, ...props },
  ref,
) {
  const { t } = useTranslation()
  const listId = useId()
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const query = useSettled(value.trim())
  const search = useContactEmailSearch(query, open && query.length >= 2)
  const matches = (search.data ?? []).filter((match) => match.address !== value.trim().toLowerCase()).slice(0, 8)
  const showing = open && query.length >= 2 && matches.length > 0

  useEffect(() => setActive(0), [query])

  function pick(match: ContactEmailMatch) {
    onValueChange(match.address)
    setOpen(false)
    onPick?.(match)
  }

  return (
    <div className="relative min-w-0 flex-1">
      <Input
        ref={ref}
        {...props}
        role="combobox"
        aria-expanded={showing}
        aria-controls={listId}
        aria-autocomplete="list"
        aria-activedescendant={showing ? `${listId}-${active}` : undefined}
        autoComplete="off"
        autoCapitalize="off"
        spellCheck={false}
        className={className}
        value={value}
        onChange={(e) => {
          onValueChange(e.target.value)
          setOpen(true)
        }}
        onKeyDown={(e) => {
          if (showing && e.key === 'ArrowDown') {
            e.preventDefault()
            setActive((i) => (i + 1) % matches.length)
          } else if (showing && e.key === 'ArrowUp') {
            e.preventDefault()
            setActive((i) => (i - 1 + matches.length) % matches.length)
          } else if (showing && e.key === 'Enter') {
            e.preventDefault()
            pick(matches[active])
          } else if (e.key === 'Escape' && showing) {
            e.stopPropagation()
            setOpen(false)
          }
          onKeyDown?.(e)
        }}
        onBlur={(e) => {
          // Suggestions keep the focus (mousedown is prevented), so a blur
          // means the person left the field. Closing later would race the
          // next keystrokes and hide the list they asked for.
          setOpen(false)
          onBlur?.(e)
        }}
      />
      {showing ? (
        <ul
          id={listId}
          role="listbox"
          aria-label={t('contactSuggest.label')}
          className="absolute inset-x-0 top-full z-50 mt-1 max-h-64 overflow-y-auto rounded-md border border-border bg-popover p-1 text-popover-foreground shadow-md"
        >
          {matches.map((match, i) => (
            <li
              key={`${match.contactId}-${match.address}`}
              id={`${listId}-${i}`}
              role="option"
              aria-selected={i === active}
              onMouseDown={(e) => e.preventDefault()}
              onMouseEnter={() => setActive(i)}
              onClick={() => pick(match)}
              className={cn('cursor-pointer rounded-sm px-2 py-1.5 text-sm', i === active && 'bg-accent text-accent-foreground')}
            >
              <span className="block truncate font-medium">{match.name}</span>
              <span className="block truncate text-xs text-muted-foreground">{match.address}</span>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  )
})
