import { ChevronDown, ChevronRight, HardDrive, Users } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { cn } from '@kutup/ui/lib/cn'
import { folderHex } from '../drive/colors'
import type { FolderIndex } from '@kutup/drive-core/folders'
import type { Folder } from '@kutup/drive-core/model'
import { KindIcon } from '@kutup/drive-ui/KindIcon'

/**
 * Choose a destination folder: My files as a tree, then the folders shared
 * with you. Folders that cannot take the items are shown but disabled, with
 * the reason as their tooltip, so the tree keeps its shape.
 */
export function FolderPickerDialog({
  open,
  title,
  description,
  submit,
  index,
  start,
  refusal,
  pending,
  onClose,
  onPick,
}: {
  open: boolean
  title: string
  description?: string
  submit: string
  index: FolderIndex
  /** Opened at, and pre-selected: usually the folder on screen. */
  start: Folder | null
  /** Why a folder cannot be picked, or null when it can. */
  refusal: (folder: Folder) => string | null
  pending?: boolean
  onClose: () => void
  onPick: (folder: Folder) => void
}) {
  const { t } = useTranslation()
  const [picked, setPicked] = useState<Folder | null>(null)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  useEffect(() => {
    if (!open) return
    // Open the tree down to where we are.
    const trail = new Set<string>([index.root.id])
    let at = start?.parentId ? index.byId.get(start.parentId) : undefined
    while (at) {
      trail.add(at.id)
      at = at.parentId ? index.byId.get(at.parentId) : undefined
    }
    setExpanded(trail)
    setPicked(start && !refusal(start) ? start : null)
    // Only when opened; `refusal` is recreated on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, index, start])

  const childrenOf = (folder: Folder) =>
    folder.isRoot ? [...index.childrenOf(folder.id), ...index.looseTopLevel] : index.childrenOf(folder.id)

  const byName = (a: Folder, b: Folder) => (a.name ?? '').localeCompare(b.name ?? '')

  const row = (folder: Folder, depth: number, icon?: React.ReactNode) => {
    const kids = folder.source === 'owned' ? childrenOf(folder).filter((f) => f.key).sort(byName) : []
    const isOpen = expanded.has(folder.id)
    const reason = refusal(folder)
    const label = folder.isRoot ? t('nav.myFiles') : (folder.name ?? t('drive.encrypted'))
    return (
      <li key={`${folder.source}:${folder.remoteShareId ?? folder.id}`}>
        <div className="flex items-center" style={{ paddingLeft: `${depth * 1.25}rem` }}>
          {kids.length > 0 ? (
            <Button
              variant="ghost"
              size="icon"
              className="size-7 shrink-0"
              aria-label={isOpen ? t('dialogs.picker.collapse', { name: label }) : t('dialogs.picker.expand', { name: label })}
              aria-expanded={isOpen}
              onClick={() =>
                setExpanded((prev) => {
                  const next = new Set(prev)
                  if (next.has(folder.id)) next.delete(folder.id)
                  else next.add(folder.id)
                  return next
                })
              }
            >
              {isOpen ? <ChevronDown /> : <ChevronRight />}
            </Button>
          ) : (
            <span className="size-7 shrink-0" />
          )}
          <button
            type="button"
            disabled={reason !== null}
            title={reason ?? undefined}
            aria-pressed={picked === folder}
            onClick={() => setPicked(folder)}
            onDoubleClick={() => reason === null && onPick(folder)}
            className={cn(
              'flex min-w-0 flex-1 items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm',
              'hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
              'disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:bg-transparent',
              picked === folder && 'bg-accent font-medium text-accent-foreground',
            )}
          >
            {icon ?? <KindIcon kind="folder" color={folderHex(folder.color)} className="size-4 shrink-0" />}
            <span className="truncate">{label}</span>
          </button>
        </div>
        {isOpen && kids.length > 0 ? <ul>{kids.map((kid) => row(kid, depth + 1))}</ul> : null}
      </li>
    )
  }

  const shared = index.sharedWithMe.filter((f) => f.key).sort(byName)

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description ? <DialogDescription>{description}</DialogDescription> : null}
        </DialogHeader>
        <div className="max-h-[50vh] overflow-y-auto rounded-md border border-border p-1">
          <ul aria-label={t('nav.myFiles')}>{row(index.root, 0, <HardDrive className="size-4 shrink-0" />)}</ul>
          {shared.length > 0 ? (
            <>
              <p className="flex items-center gap-2 px-2 pb-1 pt-3 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                <Users className="size-3.5" aria-hidden />
                {t('nav.shared')}
              </p>
              <ul aria-label={t('nav.shared')}>{shared.map((f) => row(f, 0))}</ul>
            </>
          ) : null}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button disabled={!picked} loading={pending} onClick={() => picked && onPick(picked)}>
            {submit}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
