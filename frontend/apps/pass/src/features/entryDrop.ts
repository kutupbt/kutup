import { useRef, useState, type DragEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { canDropGroup } from '../lib/groupMoves'
import type { VaultSession } from '../sync/vaultSession'

/** What a dragged entry row carries: the ids of the entries it moves (JSON). */
export const DRAG_TYPE = 'application/x-kutup-pass-entries'
/** What a dragged group carries: its id. */
export const GROUP_DRAG_TYPE = 'application/x-kutup-pass-group'

/**
 * A group in the sidebar as a place to drop dragged entries or a dragged
 * group: moved there, or into the recycle bin (`bin`), never deleted for
 * good. A group never drops into itself or what it holds. Nothing for a
 * read-only vault.
 */
export function useEntryDrop(session: VaultSession, onDone: (message: string) => void) {
  const { t } = useTranslation()
  const [over, setOver] = useState<string | null>(null)
  // The group being dragged: a drag's data can't be read before the drop,
  // and whether a target takes it depends on which group it is.
  const dragged = useRef<string | null>(null)

  const dropEntries = (ids: string[], target: { id: string; name: string; bin: boolean }) => {
    const entries = new Map(session.getState().view.entries.map((e) => [e.id, e]))
    // Into the bin only what isn't in it yet (never a delete for good);
    // into a group only what isn't there already.
    const moving = ids.filter((id) => {
      const entry = entries.get(id)
      return entry !== undefined && (target.bin ? !entry.inRecycleBin : entry.groupId !== target.id)
    })
    if (moving.length === 0) return
    void session
      .apply(target.bin ? { op: 'recycleEntries', ids: moving } : { op: 'moveEntries', ids: moving, groupId: target.id })
      .then(
        () => onDone(target.bin ? t('bulk.recycled', { count: moving.length }) : t('bulk.moved', { count: moving.length, group: target.name })),
        () => toast.error(t('entry.saveFailed')),
      )
  }

  const dropGroup = (id: string, target: { id: string; name: string; bin: boolean }) => {
    const view = session.getState().view
    if (!canDropGroup(view, id, target.id)) return
    const name = view.groups.find((g) => g.id === id)?.name ?? ''
    void session
      .apply(target.bin ? { op: 'recycleGroup', id } : { op: 'moveGroup', id, parentId: target.id })
      .then(
        () => onDone(target.bin ? t('groups.deleted') : t('groups.moved', { name, group: target.name })),
        // A recycle refused because the bin went off meanwhile (another
        // device): said so; anything else is a failed save.
        () => toast.error(target.bin && !session.getState().view.recycleBinEnabled ? t('bulk.binOff') : t('entry.saveFailed')),
      )
  }

  const dropProps = (target: { id: string; name: string; bin: boolean }) =>
    session.canEdit
      ? {
          onDragOver: (event: DragEvent) => {
            const types = event.dataTransfer.types
            const takes = types.includes(DRAG_TYPE) || (types.includes(GROUP_DRAG_TYPE) && dragged.current !== null && canDropGroup(session.getState().view, dragged.current, target.id))
            if (!takes) return
            event.preventDefault()
            event.dataTransfer.dropEffect = 'move'
            setOver(target.id)
          },
          onDragLeave: () => setOver((current) => (current === target.id ? null : current)),
          onDrop: (event: DragEvent) => {
            setOver(null)
            const group = event.dataTransfer.getData(GROUP_DRAG_TYPE)
            if (group) {
              event.preventDefault()
              dropGroup(group, target)
              return
            }
            let ids: string[]
            try {
              ids = JSON.parse(event.dataTransfer.getData(DRAG_TYPE)) as string[]
            } catch {
              return
            }
            if (!Array.isArray(ids) || ids.length === 0) return
            event.preventDefault()
            dropEntries(ids, target)
          },
          'data-drop-over': over === target.id ? 'true' : undefined,
        }
      : {}

  /** A group row as something to drag (not the top group: the caller leaves it out). */
  const dragProps = (id: string) =>
    session.canEdit
      ? {
          draggable: true,
          onDragStart: (event: DragEvent) => {
            dragged.current = id
            event.dataTransfer.setData(GROUP_DRAG_TYPE, id)
            event.dataTransfer.effectAllowed = 'move'
          },
          onDragEnd: () => {
            dragged.current = null
            setOver(null)
          },
        }
      : {}

  return { dropProps, dragProps, over }
}
