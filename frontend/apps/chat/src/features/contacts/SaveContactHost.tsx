import { SaveContactDialog } from '@kutup/contacts-core/ui/SaveContactDialog'
import { useSaveContact, useSaving } from './saveContactState'

/** The Save to contacts dialog, mounted once by the shell. */
export function SaveContactHost() {
  const saving = useSaving()
  const close = useSaveContact()
  if (!saving) return null
  return <SaveContactDialog key={saving.address} address={saving.address} name={saving.name} onClose={() => close(null)} />
}
