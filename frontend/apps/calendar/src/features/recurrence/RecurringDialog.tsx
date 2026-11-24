import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import type { RecurringType, SaveWarnings } from './actions'

/**
 * Proton's `EditRecurringConfirmModal` and `DeleteRecurringConfirmModal`:
 * which occurrences a change or a delete applies to (`SelectRecurringType`:
 * this event, this and future events, all events), and what it loses.
 */
export function RecurringDialog({
  mode,
  types,
  warnings,
  pending,
  error,
  onWarnings,
  onConfirm,
  onClose,
}: {
  mode: 'save' | 'delete'
  /** The choices; none: closed. */
  types: RecurringType[] | null
  warnings?: SaveWarnings | null
  pending: boolean
  error: string | null
  /** The warnings for another choice (a save's). */
  onWarnings?: (type: RecurringType) => void
  onConfirm: (type: RecurringType) => void
  onClose: () => void
}) {
  const { t } = useTranslation()
  const [type, setType] = useState<RecurringType>('single')
  useEffect(() => {
    if (types?.length) {
      setType(types[0])
      onWarnings?.(types[0])
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- once per opening
  }, [types])
  const one = types?.length === 1 ? types[0] : null
  const question =
    mode === 'delete'
      ? one === 'single'
        ? t('recurrence.deleteThis')
        : one === 'all'
          ? t('recurrence.deleteAll')
          : t('recurrence.deleteWhich')
      : one === 'single'
        ? t('recurrence.updateThis')
        : one === 'all'
          ? t('recurrence.updateAll')
          : t('recurrence.updateWhich')
  const labels: Record<RecurringType, string> = {
    single: t('recurrence.thisEvent'),
    future: t('recurrence.thisAndFuture'),
    all: t('recurrence.allEvents'),
  }
  return (
    <Dialog open={types !== null} onOpenChange={(open) => !open && !pending && onClose()}>
      <DialogContent className="max-w-md" data-testid={`recurring-${mode}`}>
        <DialogHeader>
          <DialogTitle>{mode === 'delete' ? t('recurrence.deleteTitle') : t('recurrence.updateTitle')}</DialogTitle>
          <DialogDescription>{question}</DialogDescription>
        </DialogHeader>
        <form
          className="mt-2 space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            onConfirm(type)
          }}
        >
          {types && types.length > 1 ? (
            <div className="space-y-2" role="radiogroup" aria-label={question}>
              {types.map((option) => (
                <label key={option} className="flex items-center gap-2 text-sm">
                  <input
                    type="radio"
                    name="recurring-type"
                    checked={type === option}
                    onChange={() => {
                      setType(option)
                      onWarnings?.(option)
                    }}
                    data-testid={`recurring-option-${option}`}
                  />
                  {labels[option]}
                </label>
              ))}
            </div>
          ) : null}
          {mode === 'save' && warnings?.modificationsLost ? <Alert variant="warn">{t('recurrence.modificationsLost')}</Alert> : null}
          {mode === 'save' && warnings?.ruleLost ? <Alert variant="warn">{t('recurrence.ruleLost')}</Alert> : null}
          {error ? <Alert variant="error">{error}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={onClose} disabled={pending}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" variant={mode === 'delete' ? 'destructive' : 'default'} loading={pending} data-testid="recurring-confirm">
              {mode === 'delete' ? t('recurrence.delete') : t('recurrence.update')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
