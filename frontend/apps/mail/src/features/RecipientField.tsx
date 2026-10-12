import { X } from 'lucide-react'
import { useId, useMemo, useState, type DragEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { useContactGroups, useContacts } from '@kutup/contacts-core/api'
import { displayName } from '@kutup/contacts-core/model'
import { ContactSuggestInput } from '@kutup/contacts-core/ui/ContactSuggestInput'
import type { PinnedKeys } from '@kutup/mail-core/api'
import { groupDirectory } from '@kutup/mail-core/groups'
import type { Mailbox } from '@kutup/mail-core/mime'
import { cn } from '@kutup/ui/lib/cn'
import { isAddress, parseRecipients } from './recipients'
import { RecipientLock } from './RecipientLock'

/** Groups the writer may send to, after the contacts in the suggestions. */
const GROUP_SUGGESTIONS = {
  key: 'mail-groups',
  search: async (query: string) =>
    (await groupDirectory(query)).map((group) => ({ contactId: '', name: group.displayName, address: group.address, label: null })),
}

/** A contact group in the suggestions (Proton's AddressesGroupItem): its members are added. */
const CONTACT_GROUP = 'contact-group:'

/**
 * Proton's drag between To, Cc and Bcc: the chip being dragged, and how to
 * take it out of the field it came from.
 */
let dragged: { mailbox: Mailbox; from: string; remove: () => void } | null = null
const RECIPIENT_DRAG = 'application/x-kutup-recipient'

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
  encrypt = true,
  autoFocus,
}: {
  label: string
  value: Mailbox[]
  onChange: (next: Mailbox[]) => void
  /** This server's domain: its addresses get end-to-end encryption. */
  domain: string
  /** Keys pinned in Contacts (undefined while they load). */
  pinned: PinnedKeys | undefined
  /** Encrypt is on for this message (off: the locks say so). */
  encrypt?: boolean
  autoFocus?: boolean
}) {
  const { t } = useTranslation()
  const id = useId()
  const [text, setText] = useState('')
  const [dropping, setDropping] = useState(false)
  const contactGroups = useContactGroups()
  const contacts = useContacts()
  // Mail groups (lists, shared mailboxes) and the reader's contact groups.
  const suggestions = useMemo(
    () => ({
      key: `${GROUP_SUGGESTIONS.key}:${contactGroups.dataUpdatedAt}`,
      search: async (query: string) => {
        const q = query.toLocaleLowerCase()
        const groups = (contactGroups.data ?? [])
          .filter((group) => group.members > 0 && group.name.toLocaleLowerCase().includes(q))
          .map((group) => ({ contactId: '', name: group.name, address: `${CONTACT_GROUP}${group.id}`, label: null, hint: t('compose.contactGroup', { count: group.members }) }))
        return [...groups, ...(await GROUP_SUGGESTIONS.search(query))]
      },
    }),
    [contactGroups.data, contactGroups.dataUpdatedAt, t],
  )

  /** A contact group's members, each address of each. */
  function members(groupId: string): Mailbox[] {
    return (contacts.data?.contacts ?? [])
      .filter((contact) => contact.draft.groups.includes(groupId))
      .flatMap((contact) => contact.draft.emails.map((email) => ({ address: email.address.toLowerCase(), name: displayName(contact.draft) })))
  }

  function onDrop(e: DragEvent) {
    e.preventDefault()
    setDropping(false)
    if (!dragged || dragged.from === id) return
    const { mailbox, remove } = dragged
    dragged = null
    if (!value.some((m) => m.address === mailbox.address)) onChange([...value, mailbox])
    remove()
  }

  function add(entries: Mailbox[]) {
    const known = new Set(value.map((m) => m.address))
    const fresh = entries.filter((m) => m.address && !known.has(m.address))
    if (fresh.length) onChange([...value, ...fresh])
    setText('')
  }

  return (
    <div
      role="group"
      aria-label={label}
      className={cn('flex min-h-10 flex-wrap items-center gap-1 border-b border-border px-3 py-1', dropping && 'bg-primary/5 ring-1 ring-inset ring-primary/40')}
      onDragOver={(e) => {
        if (!e.dataTransfer.types.includes(RECIPIENT_DRAG) || dragged?.from === id) return
        e.preventDefault()
        setDropping(true)
      }}
      onDragLeave={() => setDropping(false)}
      onDrop={onDrop}
    >
      <label htmlFor={id} className="w-10 shrink-0 text-sm text-muted-foreground">
        {label}
      </label>
      {value.map((mailbox) => {
        const valid = isAddress(mailbox.address)
        return (
          <span
            key={mailbox.address}
            title={mailbox.address}
            draggable
            onDragStart={(e) => {
              e.dataTransfer.setData(RECIPIENT_DRAG, mailbox.address)
              e.dataTransfer.effectAllowed = 'move'
              dragged = { mailbox, from: id, remove: () => onChange(value.filter((m) => m.address !== mailbox.address)) }
            }}
            onDragEnd={() => {
              dragged = null
            }}
            className={cn(
              'inline-flex max-w-full items-center gap-1 rounded-full border px-2 py-0.5 text-sm',
              valid ? 'border-border bg-muted/60' : 'border-destructive text-destructive',
            )}
          >
            {valid ? <RecipientLock address={mailbox.address} domain={domain} pinned={pinned} encrypt={encrypt} /> : null}
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
        onPick={(match) =>
          add(match.address.startsWith(CONTACT_GROUP) ? members(match.address.slice(CONTACT_GROUP.length)) : [{ address: match.address, name: match.name }])
        }
        extraSuggestions={suggestions}
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
