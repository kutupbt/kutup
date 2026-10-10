import { X } from 'lucide-react'
import { useId, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ContactSuggestInput } from '@kutup/contacts-core/ui/ContactSuggestInput'
import type { PinnedKeys } from '@kutup/mail-core/api'
import type { Mailbox } from '@kutup/mail-core/mime'
import { cn } from '@kutup/ui/lib/cn'
import { isAddress, parseRecipients } from './recipients'
import { RecipientLock } from './RecipientLock'

/**
 * To, Cc or Bcc: chips for the people added, and a field that suggests from
 * Contacts. Comma, semicolon, Enter or leaving the field adds what is typed;
 * Backspace on an empty field takes the last one off.
 */
export function RecipientField({
  label,
  value,
  onChange,
  domain,
  pinned,
  autoFocus,
}: {
  label: string
  value: Mailbox[]
  onChange: (next: Mailbox[]) => void
  /** This server's domain: its addresses get end-to-end encryption. */
  domain: string
  /** Keys pinned in Contacts (undefined while they load). */
  pinned: PinnedKeys | undefined
  autoFocus?: boolean
}) {
  const { t } = useTranslation()
  const id = useId()
  const [text, setText] = useState('')

  function add(entries: Mailbox[]) {
    const known = new Set(value.map((m) => m.address))
    const fresh = entries.filter((m) => m.address && !known.has(m.address))
    if (fresh.length) onChange([...value, ...fresh])
    setText('')
  }

  return (
    <div className="flex min-h-10 flex-wrap items-center gap-1 border-b border-border px-3 py-1">
      <label htmlFor={id} className="w-10 shrink-0 text-sm text-muted-foreground">
        {label}
      </label>
      {value.map((mailbox) => {
        const valid = isAddress(mailbox.address)
        return (
          <span
            key={mailbox.address}
            title={mailbox.address}
            className={cn(
              'inline-flex max-w-full items-center gap-1 rounded-full border px-2 py-0.5 text-sm',
              valid ? 'border-border bg-muted/60' : 'border-destructive text-destructive',
            )}
          >
            {valid ? <RecipientLock address={mailbox.address} domain={domain} pinned={pinned} /> : null}
            <span className="truncate">{mailbox.name || mailbox.address}</span>
            {!valid ? <span className="sr-only">{t('compose.invalidAddress')}</span> : null}
            <button
              type="button"
              className="rounded-full p-0.5 hover:bg-muted"
              aria-label={t('compose.removeRecipient', { address: mailbox.address })}
              onClick={() => onChange(value.filter((m) => m.address !== mailbox.address))}
            >
              <X className="size-3" />
            </button>
          </span>
        )
      })}
      <ContactSuggestInput
        id={id}
        value={text}
        autoFocus={autoFocus}
        onValueChange={(next) => {
          if (/[,;]/.test(next)) add(parseRecipients(next))
          else setText(next)
        }}
        onPick={(match) => add([{ address: match.address, name: match.name }])}
        onKeyDown={(e) => {
          // A suggestion was picked: that added it already.
          if (e.defaultPrevented) return
          if (e.key === 'Enter' && text.trim()) {
            e.preventDefault()
            add(parseRecipients(text))
          } else if (e.key === 'Backspace' && !text && value.length) {
            onChange(value.slice(0, -1))
          }
        }}
        onBlur={() => {
          if (text.trim()) add(parseRecipients(text))
        }}
        onPaste={(e) => {
          const pasted = e.clipboardData.getData('text')
          if (/[,;\n]/.test(pasted)) {
            e.preventDefault()
            add(parseRecipients(pasted))
          }
        }}
        className="h-8 min-w-[10rem] border-0 px-1 shadow-none focus-visible:ring-0"
      />
    </div>
  )
}
