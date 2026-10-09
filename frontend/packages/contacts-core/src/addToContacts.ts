import { toast } from 'sonner'
import { appUrl } from '@kutup/session/apps'
import api from '@kutup/session/client'

/**
 * After sharing with or messaging someone, offers to add them to the address
 * book when they are not in it yet (docs/plans/contacts.md: never added
 * without the person's action). The Contacts app opens with them filled in.
 */
export async function offerAddToContacts(address: string, labels: { message: string; action: string }) {
  const lower = address.trim().toLowerCase()
  if (!lower.includes('@')) return
  try {
    const { data } = await api.get<{ address: string }[]>('/contacts/emails', { params: { q: lower, limit: 5 } })
    if (data.some((match) => match.address === lower)) return
  } catch {
    return
  }
  toast(labels.message, {
    action: { label: labels.action, onClick: () => window.open(appUrl('contacts', `/?add=${encodeURIComponent(lower)}`), '_blank', 'noopener') },
  })
}
