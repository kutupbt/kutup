import type { ContactDraft } from '@kutup/contacts-core/model'
import { displayName } from '@kutup/contacts-core/model'
import { Avatar } from '@kutup/ui/components/avatar'

/** A contact's photo, else their initials. */
export function ContactAvatar({ draft, size }: { draft: ContactDraft; size: 32 | 48 | 80 }) {
  const match = draft.photo.match(/^data:(image\/[a-z+.-]+);base64,(.+)$/)
  return <Avatar name={displayName(draft)} image={match?.[2]} contentType={match?.[1]} size={size} />
}
