import { UserPlus, X } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useContactLookup } from '@kutup/contacts-core/api'
import { Button } from '@kutup/ui/components/button'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { useSaveContact } from './saveContactState'
import { getSession } from '@kutup/session/store'

/**
 * Above a one-to-one conversation with someone who is not in the address
 * book: their name, Save to contacts and a dismiss (docs/plans/contacts.md:
 * never saved without the person's action). It stays until they are saved
 * or it is dismissed, which this device remembers, so it is not a toast
 * that is gone before it is read.
 */
export function NotInContactsBanner({ address, name }: { address: string; name?: string }) {
  const { t } = useTranslation()
  const contacts = useContactLookup()
  const save = useSaveContact()
  const [dismissed, setDismissed] = useState(readDismissed)
  const key = address.toLowerCase()
  if (!contacts.ready || contacts.find(key) || dismissed.has(key)) return null
  return (
    <div className="flex items-center gap-2 border-b border-border bg-muted/50 px-4 py-1.5 text-sm" data-testid="chat-not-in-contacts">
      <UserPlus className="size-4 shrink-0 text-muted-foreground" aria-hidden />
      <span className="min-w-0 flex-1 truncate">{t('chat.contacts.notInContacts', { name: name || address })}</span>
      <Button variant="outline" size="sm" onClick={() => save({ address, name })}>
        {t('chat.contacts.save')}
      </Button>
      <Tooltip label={t('chat.contacts.dismiss')}>
        <Button
          variant="ghost"
          size="icon"
          className="size-7"
          aria-label={t('chat.contacts.dismiss')}
          onClick={() => {
            const next = new Set(dismissed).add(key)
            setDismissed(next)
            writeDismissed(next)
          }}
        >
          <X />
        </Button>
      </Tooltip>
    </div>
  )
}

const DISMISSED = 'kutup.chat.notInContactsDismissed'

/** Per account: two accounts in one browser keep their own lists. */
function dismissedKey(): string | null {
  const userId = getSession()?.userId
  return userId ? `${DISMISSED}:${userId}` : null
}

function readDismissed(): Set<string> {
  try {
    // The unkeyed list from before was shared by every account here.
    localStorage.removeItem(DISMISSED)
  } catch {
    // Storage blocked.
  }
  const key = dismissedKey()
  if (!key) return new Set()
  try {
    return new Set(JSON.parse(localStorage.getItem(key) ?? '[]') as string[])
  } catch {
    return new Set()
  }
}

function writeDismissed(addresses: Set<string>) {
  const key = dismissedKey()
  if (!key) return
  try {
    localStorage.setItem(key, JSON.stringify([...addresses].slice(-500)))
  } catch {
    // Private windows: dismissed for this page only.
  }
}
