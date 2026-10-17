import { BookUser, UserPlus } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { appUrl } from '@kutup/session/apps'
import { Button } from '@kutup/ui/components/button'
import { useContactFor } from './contactFor'
import { useSaveContact } from './saveContactState'

/**
 * Under the person in the details panel: whether they are in the address
 * book. Signal says "is in your system contacts"; Kutup's address book is
 * its own, so a person who is not in it can be saved from here, and one who
 * is opens in Contacts.
 */
export function ContactEntry({ peer, address, name }: { peer: string; address: string; name?: string }) {
  const { t } = useTranslation()
  const { ready, card: contact, taken } = useContactFor(peer, address)
  const save = useSaveContact()
  // A card saved for this address is someone else's: nothing to show or save.
  if (!ready || taken) return null
  if (contact) {
    return (
      <p className="flex items-center gap-1.5 text-sm text-muted-foreground" data-testid="chat-in-contacts">
        <BookUser className="size-4" aria-hidden />
        {t('chat.contacts.inContacts')}
        <a
          className="font-medium text-primary underline-offset-4 hover:underline"
          href={appUrl('contacts', `/c/${contact.id}`)}
          target="_blank"
          rel="noopener noreferrer"
        >
          {t('chat.contacts.view')}
        </a>
      </p>
    )
  }
  return (
    <Button variant="outline" size="sm" className="mt-2" onClick={() => save({ address, name })} data-testid="chat-save-contact">
      <UserPlus />
      {t('chat.contacts.save')}
    </Button>
  )
}
