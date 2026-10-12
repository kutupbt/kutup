import { Trans, useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import type { AllAction } from './selectAll'

const bold = { strong: <strong className="font-semibold" /> }

/**
 * Proton's SelectAllBanner, over the list once a whole page is checked:
 * how many are chosen, and "Select all N in <place>" (then Clear selection).
 */
export function SelectAllBanner({ on, conversations, page, total, location, onToggle }: { on: boolean; conversations: boolean; page: number; total: number; location: string; onToggle: () => void }) {
  const { t } = useTranslation()
  const count = on ? total : page
  return (
    <div role="status" className="flex flex-wrap items-center justify-center gap-x-2 gap-y-1 border-b border-border bg-muted/40 px-3 py-2 text-center text-sm">
      <span>
        <Trans i18nKey={`selectAll.selected.${conversations ? 'conversations' : 'messages'}`} count={count} values={{ count }} components={bold} />
      </span>
      <Button variant="link" size="sm" className="h-auto p-0" onClick={onToggle}>
        {on ? t('selectAll.clear') : t('selectAll.selectAll', { count: total, location })}
      </Button>
    </div>
  )
}

/** Proton's select-all modals (SelectAllMoveModal, SelectAllMarkModal, SelectAllLabelModal): what will happen to how many, before it does. */
export function SelectAllConfirm({
  action,
  count,
  conversations,
  destination,
  labelName,
  pending,
  onCancel,
  onConfirm,
}: {
  action: AllAction | null
  count: number
  conversations: boolean
  /** The move's destination, named. */
  destination: string
  labelName: (id: string) => string
  pending: boolean
  onCancel: () => void
  onConfirm: () => void
}) {
  const { t } = useTranslation()
  const unit = conversations ? 'conversations' : 'messages'
  if (!action) return null
  const title =
    action.kind === 'move' ? t(`selectAll.move.title.${unit}`) : action.kind === 'mark' ? t(`selectAll.mark.title.${action.seen ? 'read' : 'unread'}.${unit}`) : t(`selectAll.label.title.${unit}`)
  const submit = action.kind === 'move' ? t('selectAll.move.submit') : action.kind === 'mark' ? t(action.seen ? 'selectAll.mark.read' : 'selectAll.mark.unread') : t('selectAll.label.submit')
  return (
    <Dialog open onOpenChange={(open) => !open && !pending && onCancel()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            {action.kind === 'move'
              ? t(`selectAll.move.body.${unit}`, { count, name: destination })
              : action.kind === 'mark'
                ? t(`selectAll.mark.body.${action.seen ? 'read' : 'unread'}.${unit}`, { count })
                : null}
          </DialogDescription>
        </DialogHeader>
        {action.kind === 'label' ? (
          <div className="space-y-3 text-sm">
            {action.add.length ? (
              <div>
                <p>{t(`selectAll.label.added.${unit}`, { count })}</p>
                <ul className="mt-1 list-disc pl-5">
                  {action.add.map((id) => (
                    <li key={id}>{labelName(id)}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            {action.remove.length ? (
              <div>
                <p>{t(`selectAll.label.removed.${unit}`, { count })}</p>
                <ul className="mt-1 list-disc pl-5">
                  {action.remove.map((id) => (
                    <li key={id}>{labelName(id)}</li>
                  ))}
                </ul>
              </div>
            ) : null}
          </div>
        ) : null}
        <DialogFooter>
          <Button variant="outline" onClick={onCancel} disabled={pending}>
            {t('common.cancel')}
          </Button>
          <Button onClick={onConfirm} disabled={pending}>
            {submit}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
