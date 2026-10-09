import { displayName, type Contact } from '@kutup/contacts-core/model'
import { toVCard } from '@kutup/contacts-core/vcard'

/** Saves contacts as one .vcf file (vCard 4.0), as Proton's export does. */
export function downloadVCards(contacts: Contact[]) {
  const text = contacts.map((contact) => toVCard(contact.draft, contact.uid, displayName(contact.draft))).join('')
  const url = URL.createObjectURL(new Blob([text], { type: 'text/vcard;charset=utf-8' }))
  const link = document.createElement('a')
  link.href = url
  link.download = contacts.length === 1 ? `${displayName(contacts[0].draft) || 'contact'}.vcf` : 'contacts.vcf'
  link.click()
  URL.revokeObjectURL(url)
}
