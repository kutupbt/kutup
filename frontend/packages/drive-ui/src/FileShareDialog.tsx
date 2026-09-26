import { User } from 'lucide-react'
import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Avatar } from '@kutup/ui/components/avatar'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { isAxiosError } from 'axios'
import { AccessChanged } from '@kutup/drive-core/access'
import { CannotShareWithSelf, useFileAccess, useRemoveFileAccess, useSetEditorsCanShare, useShareFile, type ShareRole } from '@kutup/drive-core/fileShares'
import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { RecipientNotFound } from '@kutup/drive-core/mutations'
import { personOf, usePeople } from '@kutup/drive-core/people'

export type FileShareTarget = { folder: Folder; file: DriveFile; role: ShareRole }

/**
 * Share one file with someone on this server, like Proton Drive and CryptPad
 * (docs/plans/drive-file-sharing.md): they get the file's own key, never its
 * folder's. The owner shares, changes and removes; an editor the owner lets
 * share adds people. Used by Drive and by Maps (a place list is a Drive file).
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
          toast.success(t('fileShare.shared', { account: result.account }))
        },
      },
    )
  }

  const errorText = share.error
    ? isAxiosError(share.error) && share.error.response?.status === 409 && target?.role === 'editor'
      ? t('fileShare.alreadyHas')
      : share.error instanceof RecipientNotFound
      ? t('fileShare.notFound')
      : share.error instanceof CannotShareWithSelf
        ? t('fileShare.self')
        : share.error instanceof AccessChanged
          ? t('fileShare.changed')
          : apiErrorMessage(share.error, t('fileShare.failed'))
    : null

  return (
    <Dialog open={target !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('fileShare.title', { name: target?.file.name ?? '' })}</DialogTitle>
          <DialogDescription>{t('fileShare.description')}</DialogDescription>
        </DialogHeader>
        <form className="space-y-4" onSubmit={submit}>
          <Field label={t('fileShare.recipient')} description={t('fileShare.recipientHint')} required>
            {(field) => (
              <Input {...field} value={recipient} onChange={(e) => setRecipient(e.target.value)} autoFocus type="email"
                autoComplete="off" autoCapitalize="off" spellCheck={false} placeholder="alice@example.org" />
            )}
          </Field>
          <div className="flex items-start gap-2">
            <Checkbox id="share-file-edit" checked={canEdit} onCheckedChange={(v) => setCanEdit(v === true)} />
            <div>
              <Label htmlFor="share-file-edit">{t('fileShare.canEdit')}</Label>
              <p className="text-xs text-muted-foreground">{t('fileShare.canEditHint')}</p>
            </div>
          </div>
          <Alert>{t('fileShare.note')}</Alert>
          {errorText ? <Alert variant="error">{errorText}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>{t('common.close')}</Button>
            <Button type="submit" loading={share.isPending} disabled={!recipient.trim()}>
              {t('fileShare.submit')}
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
  const access = useFileAccess(target.file, target.role)
  const setEditorsCanShare = useSetEditorsCanShare()
  const owner = target.role === 'owner'
  const remove = useRemoveFileAccess()
  const people = usePeople()
  const [pending, setPending] = useState<{ userId: string; name: string } | null>(null)

  if (access.isPending) return <LoadingPanel label={t('fileShare.loading')} />
  if (access.isError || !access.data) return <Alert variant="error">{t('fileShare.loadFailed')}</Alert>
  const { members } = access.data

  function confirm() {
    if (!pending) return
    remove.mutate(
      { ...target, removed: [pending.userId] },
      {
        onSuccess: () => {
          setPending(null)
          toast.success(t('fileShare.removed'))
        },
        onError: () => setPending(null),
      },
    )
  }

  const error = remove.error
    ? remove.error instanceof AccessChanged
      ? t('fileShare.changed')
      : t('fileShare.removeFailed')
    : null

  return (
    <section className="space-y-3" aria-label={t('fileShare.accessTitle')}>
      <h3 className="text-sm font-semibold">{t('fileShare.accessTitle')}</h3>
      {members.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t('fileShare.empty')}</p>
      ) : (
        <ul className="divide-y divide-border rounded-md border border-border">
          {members.map((m) => {
            const person = personOf(people.data, m.account)
            const permission = m.canEdit ? t('fileShare.canEdit') : t('fileShare.canView')
            const behind = m.keyGeneration < access.data.keyGeneration ? t('fileShare.updating') : null
            return (
              <Row
                key={m.userId}
                icon={person.profile ? <PersonAvatar {...person} /> : <User className="size-4" aria-hidden />}
                name={person.name}
                detail={[person.profile ? m.account : null, permission, behind].filter(Boolean).join(' · ')}
                onRemove={owner ? () => setPending({ userId: m.userId, name: person.name }) : undefined}
                removeLabel={t('fileShare.removeNamed', { name: person.name })}
                busy={remove.isPending}
              />
            )
          })}
        </ul>
      )}
      {pending ? (
        <Alert variant="warn">
          <p className="font-medium">{t('fileShare.confirmTitle', { name: pending.name })}</p>
          <p className="mt-1 text-sm">{t('fileShare.confirmBody')}</p>
          <div className="mt-3 flex justify-end gap-2">
            <Button size="sm" variant="outline" onClick={() => setPending(null)} disabled={remove.isPending}>
              {t('common.cancel')}
            </Button>
            <Button size="sm" variant="destructive" onClick={confirm} loading={remove.isPending}>
              {t('fileShare.remove')}
            </Button>
          </div>
        </Alert>
      ) : null}
      {error ? <Alert variant="error">{error}</Alert> : null}
      {owner ? (
        <div className="flex items-start gap-2 border-t border-border pt-3">
          <Checkbox
            id="file-editors-share"
            checked={access.data.editorsCanShare}
            disabled={setEditorsCanShare.isPending}
            onCheckedChange={(v) => setEditorsCanShare.mutate({ file: target.file, value: v === true })}
          />
          <div>
            <Label htmlFor="file-editors-share">{t('fileShare.editorsCanShare')}</Label>
            <p className="text-xs text-muted-foreground">{t('fileShare.editorsCanShareHint')}</p>
          </div>
        </div>
      ) : (
        <p className="text-xs text-muted-foreground">{t('fileShare.onlyOwnerRemoves')}</p>
      )}
      {setEditorsCanShare.error ? <Alert variant="error">{t('fileShare.settingFailed')}</Alert> : null}
    </section>
  )
}

function PersonAvatar({ name, profile }: ReturnType<typeof personOf>) {
  return <Avatar name={name} image={profile?.avatar} contentType={profile?.avatarContentType} size={24} />
}

function Row({
  icon,
  name,
  detail,
  onRemove,
  removeLabel,
  busy,
}: {
  icon: ReactNode
  name: string
  detail: string
  /** Absent: this person cannot be removed from here (only the owner removes). */
  onRemove?: () => void
  removeLabel: string
  busy: boolean
}) {
  const { t } = useTranslation()
  return (
    <li className="flex items-center gap-3 px-3 py-2">
      <span className="text-muted-foreground">{icon}</span>
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-medium">{name}</p>
        <p className="truncate text-xs text-muted-foreground">{detail}</p>
      </div>
      {onRemove ? (
        <Button size="sm" variant="ghost" onClick={onRemove} disabled={busy} aria-label={removeLabel}>
          {t('fileShare.remove')}
        </Button>
      ) : null}
    </li>
  )
}
