import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useUpdateMessages, type FolderId, type MailMessage, type MessageChange } from '@kutup/mail-core/api'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'

/** Where a move can send mail; Inbox means home: received mail to the Inbox, sent mail to Sent. */
export type MoveTarget = 'inbox' | 'archive' | 'spam' | 'trash'

/** A move to a fixed place, or into one of the account's folders (docs/plans/mail-filters.md). */
export type Destination = MoveTarget | { folder: string; name: string }

/** The moves a folder offers: home, archive, spam, trash, never where the mail already is; drafts are deleted, not filed. */
export function movesFor(folder: FolderId): MoveTarget[] {
  if (folder === 'drafts') return []
  const all: MoveTarget[] = ['inbox', 'archive', 'spam', 'trash']
  return all.filter((target) => target !== folder && !(folder === 'sent' && target === 'spam'))
}

/** What a move needs to know of a message (also what a dragged row carries). */
export type Movable = Pick<MailMessage, 'id' | 'folder' | 'direction'> & { customFolder?: string | null }

/** Drag data for mail rows dropped on a folder: JSON `Movable[]`. */
export const MAIL_DRAG_TYPE = 'application/x-kutup-mail'

/** One place mail can be in: a fixed folder, or `custom` with its folder. */
interface Place {
  folder: NonNullable<MessageChange['folder']>
  customFolder?: string
}

const placeKey = (place: Place) => `${place.folder}:${place.customFolder ?? ''}`

/**
 * Moves, labels, read state and stars for a set of messages, from the
 * list's toolbar, its right-click menu, keyboard shortcuts and drops on a
 * folder. A move can be undone from its toast (Proton's "Undo"): each
 * message goes back to the place it came from.
 */
export function useMailActions() {
  const { t } = useTranslation()
  const update = useUpdateMessages()

  const failed = (error: unknown) => toast.error(apiErrorMessage(error, t('common.tryAgain')))

  async function moveEach(groups: Map<string, { place: Place; ids: string[] }>) {
    await Promise.all([...groups.values()].map(({ place, ids }) => update.mutateAsync({ ids, ...place })))
  }

  function move(messages: Movable[], destination: Destination, after?: () => void) {
    // Drafts stay drafts: they are deleted, not filed.
    const movable = messages.filter((m) => m.folder !== 'drafts')
    if (movable.length === 0) return
    const forward = new Map<string, { place: Place; ids: string[] }>()
    const back = new Map<string, { place: Place; ids: string[] }>()
    const add = (map: typeof forward, place: Place, id: string) => {
      const key = placeKey(place)
      const entry = map.get(key) ?? { place, ids: [] }
      entry.ids.push(id)
      map.set(key, entry)
    }
    for (const message of movable) {
      const to: Place =
        typeof destination === 'object'
          ? { folder: 'custom', customFolder: destination.folder }
          : { folder: destination === 'inbox' ? (message.direction === 'outbound' ? 'sent' : 'inbox') : destination }
      const from: Place =
        message.folder === 'custom'
          ? { folder: 'custom', customFolder: message.customFolder ?? undefined }
          : // Drafts were left out above.
            { folder: message.folder as Place['folder'] }
      if (placeKey(from) === placeKey(to)) continue
      add(forward, to, message.id)
      add(back, from, message.id)
    }
    if (forward.size === 0) return
    const count = [...forward.values()].reduce((sum, { ids }) => sum + ids.length, 0)
    moveEach(forward).then(
      () => {
        after?.()
        const done = typeof destination === 'object' ? t('moved.folder', { count, name: destination.name }) : t(`moved.${destination}`, { count })
        toast.success(done, {
          action: { label: t('moved.undo'), onClick: () => void moveEach(back).catch(failed) },
        })
      },
      failed,
    )
  }

  function mark(messages: Pick<MailMessage, 'id'>[], change: Omit<MessageChange, 'ids' | 'folder' | 'customFolder'>, after?: () => void) {
    if (messages.length === 0) return
    update.mutate({ ids: messages.map((m) => m.id), ...change }, { onSuccess: () => after?.(), onError: failed })
  }

  return { move, mark, pending: update.isPending }
}
