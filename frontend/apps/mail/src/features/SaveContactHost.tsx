import { SaveContactDialog } from '@kutup/contacts-core/ui/SaveContactDialog'
import { useSaveContact, useSaving } from './saveContactState'

/** The Save to contacts dialog, mounted once by the shell. */
export function SaveContactHost() {
  const mailbox = useSaving()
  const close = useSaveContact()
  if (!mailbox) return null
  return <SaveContactDialog key={mailbox.address} address={mailbox.address} name={mailbox.name} onClose={() => close(null)} />
}
