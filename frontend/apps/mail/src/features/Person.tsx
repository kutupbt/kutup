import { useQuery } from '@tanstack/react-query'
import { BookUser, Copy, MessageSquare, PenSquare, Phone, Search, UserPlus } from 'lucide-react'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import type { Contact } from '@kutup/contacts-core/model'
import { useMailAccount } from '@kutup/mail-core/api'
import { addressKeys, NoKutupAddress } from '@kutup/mail-core/keys'
import type { Mailbox } from '@kutup/mail-core/mime'
import { appUrl } from '@kutup/session/apps'
import { Avatar } from '@kutup/ui/components/avatar'
import { Popover, PopoverContent, PopoverTrigger } from '@kutup/ui/components/popover'
import { Separator } from '@kutup/ui/components/separator'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { cn } from '@kutup/ui/lib/cn'
import { openComposer } from './composerState'
import { nameFor } from './personName'
import { useSaveContact } from './saveContactState'

export function PersonAvatar({ mailbox, contact, size = 32 }: { mailbox: Mailbox | null | undefined; contact?: Contact; size?: 32 | 48 }) {
  const photo = contact?.draft.photo.match(/^data:(image\/[a-z+.-]+);base64,(.+)$/)
  return <Avatar name={nameFor(mailbox, contact) || '?'} image={photo?.[2]} contentType={photo?.[1]} size={size} />
}

/**
 * The Kutup account behind an address on this server (`username@server`, the
 * Chat identity), from its key list, which the account signed: mail from
 * outside can claim a Kutup address in From, but not this. Null for anyone
 * else, so Chat and Call show only for real Kutup users.
 */
function useKutupAccount(address: string, enabled: boolean) {
  const account = useMailAccount()
  const domain = account.data?.domain
  const local = !!domain && address.toLowerCase().endsWith(`@${domain.toLowerCase()}`)
  return useQuery({
    queryKey: ['mail', 'kutup-account', address.toLowerCase()],
    enabled: enabled && local,
    staleTime: 15 * 60_000,
    retry: false,
    queryFn: () =>
      addressKeys(address).then(
        (keys) => keys.account,
        (error: unknown) => {
          if (error instanceof NoKutupAddress) return null
          throw error
        },
      ),
  })
}

/** Where Chat opens a direct conversation (`apps/chat` `pathForAddress`). */
function chatUrl(account: string, call?: 'audio') {
  return appUrl('chat', `/c/${encodeURIComponent(`direct:${account}`)}${call ? `?call=${call}` : ''}`)
}

function Item({ icon, children, onClick }: { icon: ReactNode; children: ReactNode; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm hover:bg-muted focus-visible:bg-muted focus-visible:outline-none [&_svg]:size-4 [&_svg]:text-muted-foreground"
    >
      {icon}
      {children}
    </button>
  )
}

/**
 * A sender or recipient: their name, and on hover or click a card (Proton's
 * recipient dropdown) with the address to copy, New message, the contact or
 * Save to contacts, and their other mail.
 */
export function Person({
  mailbox,
  contact,
  role,
  own,
  className,
  children,
}: {
  mailbox: Mailbox
  contact: Contact | undefined
  role: 'sender' | 'recipient'
  /** The reader's own address: nothing to save. */
  own?: boolean
  className?: string
  children?: ReactNode
}) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const saveContact = useSaveContact()
  const [open, setOpen] = useState(false)
  // Opened by hovering: focus stays where it was (a click or Enter moves it into the card).
  const byHover = useRef(false)
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined)
  const name = nameFor(mailbox, contact)
  const kutup = useKutupAccount(mailbox.address, open && !own)
  useEffect(() => () => clearTimeout(timer.current), [])

  // Opens after a short hover, stays while the pointer is on the name or the card.
  const hover = {
    onPointerEnter: (e: React.PointerEvent) => {
      if (e.pointerType !== 'mouse') return
      clearTimeout(timer.current)
      timer.current = setTimeout(() => {
        byHover.current = true
        setOpen(true)
      }, 450)
    },
    onPointerLeave: (e: React.PointerEvent) => {
      if (e.pointerType !== 'mouse') return
      clearTimeout(timer.current)
      timer.current = setTimeout(() => setOpen(false), 250)
    },
  }

  function act(fn: () => void) {
    setOpen(false)
    fn()
  }

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          type="button"
          {...hover}
          onClick={(e) => {
            e.stopPropagation()
            clearTimeout(timer.current)
            byHover.current = false
            setOpen((now) => !now)
          }}
          title={mailbox.address}
          aria-label={t('person.details', { name, address: mailbox.address })}
          className={cn('max-w-full truncate rounded-sm text-left hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring', className)}
        >
          {children ?? name}
        </button>
      </PopoverTrigger>
      <PopoverContent
        align="start"
        className="w-80 p-2"
        {...hover}
        onClick={(e) => e.stopPropagation()}
        onOpenAutoFocus={(e) => {
          if (byHover.current) e.preventDefault()
        }}
      >
        <div className="flex items-center gap-3 p-2">
          <PersonAvatar mailbox={mailbox} contact={contact} size={48} />
          <div className="min-w-0 flex-1 select-text">
            <p className="truncate font-semibold">{name}</p>
            {name !== mailbox.address ? <p className="break-all text-xs text-muted-foreground">{mailbox.address}</p> : null}
            {contact?.draft.organization ? <p className="truncate text-xs text-muted-foreground">{contact.draft.organization}</p> : null}
          </div>
          <Tooltip label={t('person.copy')}>
            <button
              type="button"
              aria-label={t('person.copy')}
              className="rounded-md p-1.5 text-muted-foreground hover:bg-muted hover:text-foreground"
              onClick={() =>
                void navigator.clipboard.writeText(mailbox.address).then(
                  () => toast.success(t('person.copied')),
                  () => toast.error(t('common.tryAgain')),
                )
              }
            >
              <Copy className="size-4" />
            </button>
          </Tooltip>
        </div>
        <Separator className="my-1" />
        <Item icon={<PenSquare />} onClick={() => act(() => openComposer({ kind: 'new', to: mailbox.address }))}>
          {t('person.newMessage')}
        </Item>
        {kutup.data ? (
          <>
            <Item icon={<MessageSquare />} onClick={() => act(() => window.open(chatUrl(kutup.data!), '_blank', 'noopener'))}>
              {t('person.chat')}
            </Item>
            <Item icon={<Phone />} onClick={() => act(() => window.open(chatUrl(kutup.data!, 'audio'), '_blank', 'noopener'))}>
              {t('person.call')}
            </Item>
          </>
        ) : null}
        {contact ? (
          <Item icon={<BookUser />} onClick={() => act(() => window.open(appUrl('contacts', `/c/${contact.id}`), '_blank', 'noopener'))}>
            {t('person.viewContact')}
          </Item>
        ) : !own ? (
          <Item icon={<UserPlus />} onClick={() => act(() => saveContact(mailbox))}>
            {t('person.saveContact')}
          </Item>
        ) : null}
        <Item icon={<Search />} onClick={() => act(() => void navigate(`/all?q=${encodeURIComponent(mailbox.address)}`))}>
          {role === 'sender' ? t('person.messagesFrom') : t('person.messagesTo')}
        </Item>
      </PopoverContent>
    </Popover>
  )
}
