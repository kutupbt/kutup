import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useUpdateMessages, type FolderId, type MailMessage, type MessageChange } from '@kutup/mail-core/api'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'

/** Where a move can send mail; Inbox means home: received mail to the Inbox, sent mail to Sent. */
export type MoveTarget = 'inbox' | 'archive' | 'spam' | 'trash'

type Folder = NonNullable<MessageChange['folder']>

/** The moves a folder offers: home, archive, spam, trash, never where the mail already is; drafts are deleted, not filed. */
export function movesFor(folder: FolderId): MoveTarget[] {
  if (folder === 'drafts') return []
  const all: MoveTarget[] = ['inbox', 'archive', 'spam', 'trash']
  return all.filter((target) => target !== folder && !(folder === 'sent' && target === 'spam'))
}

/** What a move needs to know of a message (also what a dragged row carries). */
export type Movable = Pick<MailMessage, 'id' | 'folder' | 'direction'>

/** Drag data for mail rows dropped on a folder: JSON `Movable[]`. */
export const MAIL_DRAG_TYPE = 'application/x-kutup-mail'

/**
 * Moves, read state and stars for a set of messages, from the list's
 * toolbar, its right-click menu, keyboard shortcuts and drops on a folder.
 * A move can be undone from its toast (Proton's "Undo"): each message goes
 * back to the folder it came from.
 */
export function useMailActions() {
  const { t } = useTranslation()
  const update = useUpdateMessages()

  const failed = (error: unknown) => toast.error(apiErrorMessage(error, t('common.tryAgain')))

  async function moveEach(groups: Map<Folder, string[]>) {
    await Promise.all([...groups].map(([folder, ids]) => update.mutateAsync({ ids, folder })))
  }

  function move(messages: Movable[], target: MoveTarget, after?: () => void) {
    // Drafts stay drafts: they are deleted, not filed.
    const movable = messages.filter((m) => m.folder !== 'drafts')
    if (movable.length === 0) return
    const forward = new Map<Folder, string[]>()
    const back = new Map<Folder, string[]>()
    for (const message of movable) {
      const to: Folder = target === 'inbox' ? (message.direction === 'outbound' ? 'sent' : 'inbox') : target
      if (message.folder === to) continue
      forward.set(to, [...(forward.get(to) ?? []), message.id])
      const from = message.folder as Folder
      back.set(from, [...(back.get(from) ?? []), message.id])
    }
    if (forward.size === 0) return
    const count = [...forward.values()].reduce((sum, ids) => sum + ids.length, 0)
    moveEach(forward).then(
      () => {
        after?.()
        toast.success(t(`moved.${target}`, { count }), {
          action: { label: t('moved.undo'), onClick: () => void moveEach(back).catch(failed) },
        })
      },
      failed,
    )
  }

  function mark(messages: Pick<MailMessage, 'id'>[], change: Omit<MessageChange, 'ids' | 'folder'>, after?: () => void) {
    if (messages.length === 0) return
    update.mutate({ ids: messages.map((m) => m.id), ...change }, { onSuccess: () => after?.(), onError: failed })
  }

  return { move, mark, pending: update.isPending }
}
