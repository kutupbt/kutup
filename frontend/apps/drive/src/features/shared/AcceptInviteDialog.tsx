import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { apiErrorCode, apiErrorMessage } from '@kutup/ui/lib/apiError'
import { parseInvite, useAcceptInvite } from '../drive/mutations'

/** Paste an invite link someone on another Kutup server sent you. */
export function AcceptInviteDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation()
  const accept = useAcceptInvite()
  const [value, setValue] = useState('')
  const invite = parseInvite(value)

  function submit(event: FormEvent) {
    event.preventDefault()
    if (!invite) return
    accept.mutate(invite, {
      onSuccess: () => {
        toast.success(t('shared.invite.added'))
        setValue('')
        onClose()
      },
    })
  }

  const error = accept.error
    ? apiErrorCode(accept.error) === 'not_found'
      ? t('shared.invite.notFound')
      : apiErrorCode(accept.error) === 'forbidden'
        ? t('shared.invite.notForYou')
        : apiErrorMessage(accept.error, t('shared.invite.failed'))
    : null

  return (
    <Dialog open={open} onOpenChange={(o) => !o && (accept.reset(), onClose())}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('shared.invite.title')}</DialogTitle>
          <DialogDescription>{t('shared.invite.description')}</DialogDescription>
        </DialogHeader>
        <form className="space-y-4" onSubmit={submit}>
          <Field label={t('shared.invite.link')} error={value.trim() && !invite ? t('shared.invite.invalid') : undefined} required>
            {(field) => (
              <Input {...field} value={value} onChange={(e) => setValue(e.target.value)} autoFocus autoComplete="off"
                spellCheck={false} className="font-mono text-xs" placeholder="https://…/invite#server=…&capability=…" />
            )}
          </Field>
          {error ? <Alert variant="error">{error}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>{t('common.cancel')}</Button>
            <Button type="submit" loading={accept.isPending} disabled={!invite}>{t('shared.invite.submit')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
