import { User } from 'lucide-react'
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
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { AccessChanged } from '@kutup/drive-core/access'
import { CannotShareWithSelf, useFileAccess, useRemoveFileAccess, useShareFile } from '@kutup/drive-core/fileShares'
import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { RecipientNotFound } from '@kutup/drive-core/mutations'
import { personOf, usePeople } from '@kutup/drive-core/people'
import { PersonAvatar, Row } from './AccessList'

export type FileShareTarget = { folder: Folder; file: DriveFile }

/**
 * Share one file with someone on this server, like Proton Drive and CryptPad
 * (docs/plans/drive-file-sharing.md): they get the file's own key, never its
 * folder's. Only the folder's owner shares.
 */
export function FileShareDialog({ target, onClose }: { target: FileShareTarget | null; onClose: () => void }) {
  const { t } = useTranslation()
  const share = useShareFile()
  const [recipient, setRecipient] = useState('')
  const [canEdit, setCanEdit] = useState(false)

  useEffect(() => {
    if (target) {
      setRecipient('')
      setCanEdit(false)
      share.reset()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset when a new file is chosen
  }, [target?.file.id])

  function submit(event: FormEvent) {
    event.preventDefault()
    if (!target || !recipient.trim()) return
    share.mutate(
      { ...target, recipient, canEdit },
      {
        onSuccess: (result) => {
          setRecipient('')
          share.reset()
          toast.success(t('dialogs.share.shared', { account: result.account }))
        },
      },
    )
  }

  const errorText = share.error
    ? share.error instanceof RecipientNotFound
      ? t('dialogs.shareFile.notFound')
      : share.error instanceof CannotShareWithSelf
        ? t('dialogs.shareFile.self')
        : share.error instanceof AccessChanged
          ? t('dialogs.access.changed')
          : apiErrorMessage(share.error, t('dialogs.shareFile.failed'))
    : null

  return (
    <Dialog open={target !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('dialogs.share.title', { name: target?.file.name ?? '' })}</DialogTitle>
          <DialogDescription>{t('dialogs.shareFile.description')}</DialogDescription>
        </DialogHeader>
        <form className="space-y-4" onSubmit={submit}>
          <Field label={t('dialogs.shareFile.recipient')} description={t('dialogs.shareFile.recipientHint')} required>
            {(field) => (
              <Input {...field} value={recipient} onChange={(e) => setRecipient(e.target.value)} autoFocus type="email"
                autoComplete="off" autoCapitalize="off" spellCheck={false} placeholder="alice@example.org" />
            )}
          </Field>
          <div className="flex items-start gap-2">
            <Checkbox id="share-file-edit" checked={canEdit} onCheckedChange={(v) => setCanEdit(v === true)} />
            <div>
              <Label htmlFor="share-file-edit">{t('dialogs.shareFile.canEdit')}</Label>
              <p className="text-xs text-muted-foreground">{t('dialogs.shareFile.canEditHint')}</p>
            </div>
          </div>
          <Alert>{t('dialogs.shareFile.note')}</Alert>
          {errorText ? <Alert variant="error">{errorText}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>{t('common.close')}</Button>
            <Button type="submit" loading={share.isPending} disabled={!recipient.trim()}>
              {t('dialogs.share.submit')}
            </Button>
          </DialogFooter>
        </form>
        {target ? (
          <div className="border-t border-border pt-4">
            <FileAccessList target={target} />
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

/** Who the file itself is shared with; removing someone moves it to a new key. */
function FileAccessList({ target }: { target: FileShareTarget }) {
  const { t } = useTranslation()
  const access = useFileAccess(target.folder, target.file)
  const remove = useRemoveFileAccess()
  const people = usePeople()
  const [pending, setPending] = useState<{ userId: string; name: string } | null>(null)

  if (access.isPending) return <LoadingPanel label={t('dialogs.access.loading')} />
  if (access.isError || !access.data) return <Alert variant="error">{t('dialogs.access.loadFailed')}</Alert>
  const { members } = access.data

  function confirm() {
    if (!pending) return
    remove.mutate(
      { ...target, removed: [pending.userId] },
      {
        onSuccess: () => {
          setPending(null)
          toast.success(t('dialogs.access.removed'))
        },
        onError: () => setPending(null),
      },
    )
  }

  const error = remove.error
    ? remove.error instanceof AccessChanged
      ? t('dialogs.access.changed')
      : t('dialogs.access.failed')
    : null

  return (
    <section className="space-y-3" aria-label={t('dialogs.access.title')}>
      <h3 className="text-sm font-semibold">{t('dialogs.access.title')}</h3>
      {members.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t('dialogs.shareFile.empty')}</p>
      ) : (
        <ul className="divide-y divide-border rounded-md border border-border">
          {members.map((m) => {
            const person = personOf(people.data, m.account)
            const permission = m.canEdit ? t('dialogs.shareFile.canEditShort') : t('dialogs.access.canView')
            const behind = m.keyGeneration < access.data.keyGeneration ? t('dialogs.shareFile.updating') : null
            return (
              <Row
                key={m.userId}
                icon={person.profile ? <PersonAvatar {...person} /> : <User className="size-4" aria-hidden />}
                name={person.name}
                detail={[person.profile ? m.account : null, permission, behind].filter(Boolean).join(' · ')}
                onRemove={() => setPending({ userId: m.userId, name: person.name })}
                removeLabel={t('dialogs.access.removeNamed', { name: person.name })}
                busy={remove.isPending}
              />
            )
          })}
        </ul>
      )}
      {pending ? (
        <Alert variant="warn">
          <p className="font-medium">{t('dialogs.access.confirmTitle', { name: pending.name })}</p>
          <p className="mt-1 text-sm">{t('dialogs.shareFile.confirmBody')}</p>
          <div className="mt-3 flex justify-end gap-2">
            <Button size="sm" variant="outline" onClick={() => setPending(null)} disabled={remove.isPending}>
              {t('common.cancel')}
            </Button>
            <Button size="sm" variant="destructive" onClick={confirm} loading={remove.isPending}>
              {t('dialogs.access.remove')}
            </Button>
          </div>
        </Alert>
      ) : null}
      {error ? <Alert variant="error">{error}</Alert> : null}
    </section>
  )
}
