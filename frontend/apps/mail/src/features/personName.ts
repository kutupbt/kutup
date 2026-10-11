import type { Contact } from '@kutup/contacts-core/model'
import { displayName } from '@kutup/contacts-core/model'
import type { Mailbox } from '@kutup/mail-core/mime'

/** The name to show for an address: the contact's, else the mail's, else the address. */
export function nameFor(mailbox: Mailbox | null | undefined, contact: Contact | undefined): string {
  if (!mailbox) return ''
  return (contact && displayName(contact.draft)) || mailbox.name || mailbox.address
}
