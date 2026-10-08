import { useEffect, useId, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Label } from '@kutup/ui/components/label'
import { useNameConflict, type ConflictChoice } from './nameConflicts'

/**
 * An upload's name is taken in its folder: Replace (the file there goes to
 * the trash), Keep both (this one takes the next free name) or Skip, with
 * "apply to the rest" for a batch (docs/plans/drive-unique-names.md).
 * Closing the dialog skips.
 */
export function NameConflictDialog() {
  const { t } = useTranslation()
  const open = useNameConflict()
  const [all, setAll] = useState(false)
  const allId = useId()
  // Each question starts unticked.
  useEffect(() => setAll(false), [open?.question])

  if (!open) return null
  const { question } = open
  const choose = (choice: ConflictChoice) => open.answer({ choice, all })

  return (
    <Dialog open onOpenChange={(o) => !o && choose('skip')}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('uploads.conflict.title', { name: question.name })}</DialogTitle>
          <DialogDescription>
            {t(question.holder === 'folder' ? 'uploads.conflict.folderThere' : 'uploads.conflict.fileThere', { folder: question.folderName })}
          </DialogDescription>
        </DialogHeader>
        <ul className="space-y-1 text-sm text-muted-foreground">
          {question.canReplace ? <li>{t('uploads.conflict.replaceHint')}</li> : null}
          <li>{t('uploads.conflict.keepBothHint', { name: question.keptAs })}</li>
        </ul>
        {question.more ? (
          <div className="flex items-center gap-2">
            <Checkbox id={allId} checked={all} onCheckedChange={(value) => setAll(value === true)} />
            <Label htmlFor={allId} className="text-sm font-normal">
              {t('uploads.conflict.applyToAll')}
            </Label>
          </div>
        ) : null}
        <DialogFooter className="gap-2 sm:gap-2">
          <Button variant="outline" onClick={() => choose('skip')}>
            {t('uploads.conflict.skip')}
          </Button>
          <Button variant="outline" onClick={() => choose('keepBoth')}>
            {t('uploads.conflict.keepBoth')}
          </Button>
          {question.canReplace ? <Button onClick={() => choose('replace')}>{t('uploads.conflict.replace')}</Button> : null}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
