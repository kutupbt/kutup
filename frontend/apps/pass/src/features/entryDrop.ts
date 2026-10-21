import { useState, type DragEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { VaultSession } from '../sync/vaultSession'

/** What a dragged entry row carries: the ids of the entries it moves (JSON). */
export const DRAG_TYPE = 'application/x-kutup-pass-entries'

/**
 * A group in the sidebar as a place to drop dragged entries: moved there, or
 * into the recycle bin (`bin`), never deleted for good. Nothing for a
 * read-only vault.
 */
export function useEntryDrop(session: VaultSession, onDone: (message: string) => void) {
  const { t } = useTranslation()
  const [over, setOver] = useState<string | null>(null)
  const dropProps = (target: { id: string; name: string; bin: boolean }) =>
    session.canEdit
      ? {
          onDragOver: (event: DragEvent) => {
            if (!event.dataTransfer.types.includes(DRAG_TYPE)) return
            event.preventDefault()
            event.dataTransfer.dropEffect = 'move'
            setOver(target.id)
          },
          onDragLeave: () => setOver((current) => (current === target.id ? null : current)),
          onDrop: (event: DragEvent) => {
            setOver(null)
            let ids: string[]
            try {
              ids = JSON.parse(event.dataTransfer.getData(DRAG_TYPE)) as string[]
            } catch {
              return
            }
            if (!Array.isArray(ids) || ids.length === 0) return
            event.preventDefault()
            const entries = new Map(session.getState().view.entries.map((e) => [e.id, e]))
            // Into the bin only what isn't in it yet (never a delete for
            // good); into a group only what isn't there already.
            const moving = ids.filter((id) => {
              const entry = entries.get(id)
              return entry !== undefined && (target.bin ? !entry.inRecycleBin : entry.groupId !== target.id)
            })
            if (moving.length === 0) return
            void session
              .apply(target.bin ? { op: 'deleteEntries', ids: moving } : { op: 'moveEntries', ids: moving, groupId: target.id })
              .then(
                () => onDone(target.bin ? t('bulk.recycled', { count: moving.length }) : t('bulk.moved', { count: moving.length, group: target.name })),
                () => toast.error(t('entry.saveFailed')),
              )
          },
          'data-drop-over': over === target.id ? 'true' : undefined,
        }
      : {}
  return { dropProps, over }
}
