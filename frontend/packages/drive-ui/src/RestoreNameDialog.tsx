import { useCallback, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import type { AskRestoreName, RestoreNameQuestion } from '@kutup/drive-core/trash'

/**
 * Something restored from the trash whose name is taken where it comes back
 * (docs/plans/drive-unique-names.md): restore it under the first free
 * `name (n)`, or leave it in the trash. Closing the dialog leaves it.
 */
export function useRestoreNameDialog(): { ask: AskRestoreName; dialog: ReactNode } {
  const { t } = useTranslation()
  const [question, setQuestion] = useState<RestoreNameQuestion | null>(null)
  const resolver = useRef<((restore: boolean) => void) | null>(null)

  const ask = useCallback<AskRestoreName>(
    (next) =>
      new Promise<boolean>((resolve) => {
        // A question still open is answered "leave it" first.
        resolver.current?.(false)
        resolver.current = resolve
        setQuestion(next)
      }),
    [],
  )
  const answer = (restore: boolean) => {
    resolver.current?.(restore)
    resolver.current = null
    setQuestion(null)
  }

  const dialog = question ? (
    <Dialog open onOpenChange={(open) => !open && answer(false)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('restoreName.title', { name: question.name })}</DialogTitle>
          <DialogDescription>{t('restoreName.description', { name: question.suggested })}</DialogDescription>
        </DialogHeader>
        <DialogFooter className="gap-2 sm:gap-2">
          <Button variant="outline" onClick={() => answer(false)}>
            {t('restoreName.leave')}
          </Button>
          <Button onClick={() => answer(true)}>{t('restoreName.restore', { name: question.suggested })}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  ) : null
  return { ask, dialog }
}
