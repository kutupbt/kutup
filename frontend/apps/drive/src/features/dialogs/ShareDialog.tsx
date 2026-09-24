import { useQueryClient } from '@tanstack/react-query'
import { useEffect, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { apiErrorCode, apiErrorMessage } from '@kutup/ui/lib/apiError'
import type { Folder } from '../drive/model'
import { AccessList } from './AccessList'
import { accessKey } from '../drive/access'
import { RecipientNotFound, useShareFolder } from '../drive/mutations'

const GIB = 1024 ** 3

/**
 * Share a folder with someone on this server (their email) or on another
 * Kutup server (`user@server`, which returns an invite link to send them).
 * Sharing is not recursive: subfolders are shared on their own.
 */
export function ShareDialog({
  folder,
  onClose,
  onInvite,
}: {
  folder: Folder | null
  onClose: () => void
  onInvite: (link: string, account: string) => void
}) {
  const { t } = useTranslation()
  const share = useShareFolder()
  const queryClient = useQueryClient()
  const [recipient, setRecipient] = useState('')
  const [canUpload, setCanUpload] = useState(false)
  const [canDelete, setCanDelete] = useState(false)
  const [quota, setQuota] = useState('')

  useEffect(() => {
    if (folder) {
      setRecipient('')
      setCanUpload(false)
      setCanDelete(false)
      setQuota('')
      share.reset()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset when a new folder is chosen
  }, [folder?.id])

  const quotaGib = quota.trim() === '' ? null : Number(quota)
  const quotaInvalid = quotaGib !== null && !(quotaGib > 0)

  function submit(event: FormEvent) {
    event.preventDefault()
    if (!folder || !recipient.trim() || quotaInvalid) return
    share.mutate(
      {
        folder,
        recipient,
        canUpload,
        canDelete,
        uploadQuotaBytes: canUpload && quotaGib ? Math.round(quotaGib * GIB) : null,
      },
      {
        onSuccess: (result) => {
          onClose()
          void queryClient.invalidateQueries({ queryKey: accessKey(folder.id) })
          if (result.kind === 'federated') onInvite(result.inviteUrl, result.account)
          else toast.success(t('dialogs.share.shared', { account: result.account }))
        },
      },
    )
  }

  const errorText = share.error
    ? share.error instanceof RecipientNotFound || apiErrorCode(share.error) === 'not_found'
      ? t('dialogs.share.notFound')
      : apiErrorMessage(share.error, t('dialogs.share.failed'))
    : null

  return (
    <Dialog open={folder !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('dialogs.share.title', { name: folder?.name ?? '' })}</DialogTitle>
          <DialogDescription>{t('dialogs.share.description')}</DialogDescription>
        </DialogHeader>
        <form className="space-y-4" onSubmit={submit}>
          <Field label={t('dialogs.share.recipient')} description={t('dialogs.share.recipientHint')} required>
            {(field) => (
              <Input {...field} value={recipient} onChange={(e) => setRecipient(e.target.value)} autoFocus
                autoComplete="off" autoCapitalize="off" spellCheck={false} placeholder="alice@example.org" />
            )}
          </Field>
          <div className="space-y-3">
            <div className="flex items-start gap-2">
              <Checkbox id="share-upload" checked={canUpload} onCheckedChange={(v) => setCanUpload(v === true)} />
              <div>
                <Label htmlFor="share-upload">{t('dialogs.share.canUpload')}</Label>
                <p className="text-xs text-muted-foreground">{t('dialogs.share.canUploadHint')}</p>
              </div>
            </div>
            {canUpload ? (
              <Field label={t('dialogs.share.quota')} description={t('dialogs.share.quotaHint')} error={quotaInvalid ? t('dialogs.share.quotaInvalid') : undefined} className="pl-6">
                {(field) => <Input {...field} value={quota} onChange={(e) => setQuota(e.target.value)} type="number" min={0.01} step="any" inputMode="decimal" className="max-w-40" />}
              </Field>
            ) : null}
            <div className="flex items-start gap-2">
              <Checkbox id="share-delete" checked={canDelete} onCheckedChange={(v) => setCanDelete(v === true)} />
              <div>
                <Label htmlFor="share-delete">{t('dialogs.share.canDelete')}</Label>
                <p className="text-xs text-muted-foreground">{t('dialogs.share.canDeleteHint')}</p>
              </div>
            </div>
          </div>
          <Alert>{t('dialogs.share.note')}</Alert>
          {errorText ? <Alert variant="error">{errorText}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>{t('common.cancel')}</Button>
            <Button type="submit" loading={share.isPending} disabled={!recipient.trim() || quotaInvalid}>
              {t('dialogs.share.submit')}
            </Button>
          </DialogFooter>
        </form>
        {folder?.canManage ? (
          <div className="border-t border-border pt-4">
            <AccessList folder={folder} />
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}
