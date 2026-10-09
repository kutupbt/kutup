import { Check, ChevronDown, Link2, Server, User } from 'lucide-react'
import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Avatar } from '@kutup/ui/components/avatar'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@kutup/ui/components/dropdown-menu'
import { Field } from '@kutup/ui/components/field'
import { ContactSuggestInput } from '@kutup/contacts-core/ui/ContactSuggestInput'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { isAxiosError } from 'axios'
import { AccessChanged, RecipientChanged } from '@kutup/drive-core/access'
import { CannotShareWithSelf, OnlyOwnersShareAcross, fileLinkUrl, useCreateFileLink, useFileAccess, useRemoveFileAccess, useSetEditorsCanShare, useSetFileRole, useShareFile, type FileAccessMember, type ShareRole } from '@kutup/drive-core/fileShares'
import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { RecipientNotFound } from '@kutup/drive-core/mutations'
import { personOf, usePeople } from '@kutup/drive-core/people'
import { useDriveIdentity } from '@kutup/drive-core/identity'

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
  // An invite for someone on another server, to send them.
  const [invite, setInvite] = useState<{ url: string; account: string } | null>(null)

  useEffect(() => {
    if (target) {
      setRecipient('')
      setCanEdit(false)
      setInvite(null)
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
          if (result.kind === 'federated') setInvite({ url: result.inviteUrl, account: result.account })
          else toast.success(t('fileShare.shared', { account: result.account }))
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
        : share.error instanceof OnlyOwnersShareAcross
          ? t('fileShare.onlyOwnerAcross')
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
              <div className="flex gap-2">
                <ContactSuggestInput {...field} className="min-w-0 flex-1" value={recipient} onValueChange={setRecipient} autoFocus placeholder="alice@example.org" />
                <Select value={canEdit ? 'edit' : 'view'} onValueChange={(value) => setCanEdit(value === 'edit')}>
                  <SelectTrigger className="w-auto shrink-0" aria-label={t('fileShare.roleLabel')} data-testid="file-share-role">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="view">{t('fileShare.canView')}</SelectItem>
                    <SelectItem value="edit">{t('fileShare.canEdit')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}
          </Field>
          <p className="text-xs text-muted-foreground">{t('fileShare.canEditHint')}</p>
          <Alert>{t('fileShare.note')}</Alert>
          {invite ? (
            <Alert>
              <p className="font-medium">{t('fileShare.inviteTitle', { account: invite.account })}</p>
              <p className="mt-1 text-sm">{t('fileShare.inviteBody')}</p>
              <div className="mt-2 flex gap-2">
                <Input readOnly value={invite.url} aria-label={t('fileShare.inviteLink')} onFocus={(e) => e.target.select()} data-testid="file-invite-link" />
                <Button
                  type="button"
                  variant="outline"
                  onClick={() =>
                    void navigator.clipboard.writeText(invite.url).then(
                      () => toast.success(t('fileShare.linkCopied')),
                      () => toast.error(t('common.tryAgain')),
                    )
                  }
                >
                  {t('fileShare.copy')}
                </Button>
              </div>
            </Alert>
          ) : null}
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
  const setRole = useSetFileRole()
  const people = usePeople()
  // Someone, or a link, about to be removed (either moves the file to a new key).
  const [pending, setPending] = useState<{ userId?: string; linkId?: string; federatedId?: string; name: string } | null>(null)
  const createLink = useCreateFileLink()
  const identity = useDriveIdentity()
  const [newLink, setNewLink] = useState<string | null>(null)

  if (access.isPending) return <LoadingPanel label={t('fileShare.loading')} />
  if (access.isError || !access.data) return <Alert variant="error">{t('fileShare.loadFailed')}</Alert>
  const { members, publicLinks, federatedShares } = access.data

  async function copy(url: string) {
    try {
      await navigator.clipboard.writeText(url)
      toast.success(t('fileShare.linkCopied'))
    } catch {
      toast.error(t('common.tryAgain'))
    }
  }

  function confirm() {
    if (!pending) return
    remove.mutate(
      {
        ...target,
        removed: pending.userId ? [pending.userId] : [],
        removedLinks: pending.linkId ? [pending.linkId] : [],
        removedFederated: pending.federatedId ? [pending.federatedId] : [],
      },
      {
        onSuccess: () => {
          setPending(null)
          toast.success(t('fileShare.removed'))
        },
        onError: () => setPending(null),
      },
    )
  }

  function changeRole(member: FileAccessMember, name: string, canEdit: boolean) {
    if (member.canEdit === canEdit) return
    setRole.mutate(
      { ...target, member, canEdit },
      { onSuccess: () => toast.success(t(canEdit ? 'fileShare.nowEditor' : 'fileShare.nowViewer', { name })) },
    )
  }

  const busy = remove.isPending || setRole.isPending
  const error = setRole.error
    ? setRole.error instanceof AccessChanged
      ? t('fileShare.changed')
      : t('fileShare.roleFailed')
    : remove.error
    ? remove.error instanceof AccessChanged
      ? t('fileShare.changed')
      : remove.error instanceof RecipientChanged
        ? t('fileShare.recipientChanged', { account: remove.error.account })
        : t('fileShare.removeFailed')
    : null

  return (
    <section className="space-y-3" aria-label={t('fileShare.accessTitle')}>
      <h3 className="text-sm font-semibold">{t('fileShare.accessTitle')}</h3>
      {members.length + federatedShares.length === 0 ? (
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
                detail={[person.profile ? m.account : null, owner ? null : permission, behind].filter(Boolean).join(' · ')}
                control={
                  owner ? (
                    <RoleMenu
                      name={person.name}
                      canEdit={m.canEdit}
                      busy={busy}
                      onRole={(canEdit) => changeRole(m, person.name, canEdit)}
                      onRemove={() => setPending({ userId: m.userId, name: person.name })}
                    />
                  ) : null
                }
              />
            )
          })}
          {federatedShares.map((f) => {
            const account = `${f.recipientUsername}@${f.recipientServer}`
            const person = personOf(people.data, account)
            const behind = f.keyGeneration < access.data.keyGeneration ? t('fileShare.updating') : null
            return (
              <Row
                key={f.id}
                icon={person.profile ? <PersonAvatar {...person} /> : <Server className="size-4" aria-hidden />}
                name={person.name}
                detail={[person.profile ? account : null, owner ? null : f.canEdit ? t('fileShare.canEdit') : t('fileShare.canView'), t('fileShare.otherServer'), behind].filter(Boolean).join(' · ')}
                control={
                  owner ? (
                    // Across servers the role is set by the invite; changing it means a new one.
                    <RoleMenu
                      name={person.name}
                      canEdit={f.canEdit}
                      busy={busy}
                      fixedNote={t('fileShare.otherServerFixed')}
                      onRemove={() => setPending({ federatedId: f.id, name: person.name })}
                    />
                  ) : null
                }
              />
            )
          })}
        </ul>
      )}
      {pending ? (
        <Alert variant="warn">
          <p className="font-medium">{t('fileShare.confirmTitle', { name: pending.name })}</p>
          <p className="mt-1 text-sm">{pending.linkId ? t('fileShare.confirmLinkBody') : t('fileShare.confirmBody')}</p>
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
      {owner ? (
        <div className="space-y-2 border-t border-border pt-3">
          <h3 className="text-sm font-semibold">{t('fileShare.linksTitle')}</h3>
          <p className="text-xs text-muted-foreground">{t('fileShare.linksHint')}</p>
          {publicLinks.length > 0 ? (
            <ul className="divide-y divide-border rounded-md border border-border">
              {publicLinks.map((link) => (
                <li key={link.id} className="flex items-center gap-3 px-3 py-2">
                  <Link2 className="size-4 text-muted-foreground" aria-hidden />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium">{t('fileShare.link')}</p>
                    <p className="truncate text-xs text-muted-foreground">
                      {[
                        t('fileShare.linkCreated', { date: new Date(link.createdAt).toLocaleDateString() }),
                        link.keyGeneration < access.data.keyGeneration ? t('fileShare.updating') : null,
                      ]
                        .filter(Boolean)
                        .join(' · ')}
                    </p>
                  </div>
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={!identity.data}
                    onClick={() => identity.data && void fileLinkUrl(link, identity.data).then(copy, () => toast.error(t('common.tryAgain')))}
                  >
                    {t('fileShare.copy')}
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={remove.isPending}
                    onClick={() => setPending({ linkId: link.id, name: t('fileShare.link') })}
                    aria-label={t('fileShare.removeLink')}
                  >
                    {t('fileShare.remove')}
                  </Button>
                </li>
              ))}
            </ul>
          ) : null}
          {newLink ? (
            <div className="flex gap-2">
              <Input readOnly value={newLink} aria-label={t('fileShare.link')} onFocus={(e) => e.target.select()} data-testid="new-file-link" />
              <Button type="button" variant="outline" onClick={() => void copy(newLink)}>
                {t('fileShare.copy')}
              </Button>
            </div>
          ) : (
            <Button
              type="button"
              variant="outline"
              size="sm"
              loading={createLink.isPending}
              onClick={() =>
                createLink.mutate(target, {
                  onSuccess: (url) => setNewLink(url),
                })
              }
            >
              <Link2 /> {t('fileShare.createLink')}
            </Button>
          )}
          {createLink.error ? <Alert variant="error">{t('fileShare.linkFailed')}</Alert> : null}
        </div>
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

function Row({ icon, name, detail, control }: { icon: ReactNode; name: string; detail: string; control: ReactNode }) {
  return (
    <li className="flex items-center gap-3 px-3 py-2">
      <span className="text-muted-foreground">{icon}</span>
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-medium">{name}</p>
        {detail ? <p className="truncate text-xs text-muted-foreground">{detail}</p> : null}
      </div>
      {control}
    </li>
  )
}

/**
 * What someone may do with the file, and removing them, in one menu on their
 * row (as Google Drive and Proton Drive have it). Without `onRole` the role
 * is fixed and `fixedNote` says why.
 */
function RoleMenu({
  name,
  canEdit,
  busy,
  onRole,
  onRemove,
  fixedNote,
}: {
  name: string
  canEdit: boolean
  busy: boolean
  onRole?: (canEdit: boolean) => void
  onRemove: () => void
  fixedNote?: string
}) {
  const { t } = useTranslation()
  const choice = (value: boolean, label: string) => (
    <DropdownMenuItem disabled={!onRole} onSelect={() => onRole?.(value)}>
      <Check className={canEdit === value ? 'opacity-100' : 'opacity-0'} aria-hidden />
      {label}
    </DropdownMenuItem>
  )
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button size="sm" variant="ghost" disabled={busy} aria-label={t('fileShare.roleFor', { name })} className="shrink-0 gap-1">
          {canEdit ? t('fileShare.canEdit') : t('fileShare.canView')}
          <ChevronDown aria-hidden />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {choice(false, t('fileShare.canView'))}
        {choice(true, t('fileShare.canEdit'))}
        {fixedNote ? <p className="max-w-56 px-2 py-1.5 text-xs text-muted-foreground">{fixedNote}</p> : null}
        <DropdownMenuSeparator />
        <DropdownMenuItem className="text-destructive" onSelect={onRemove} aria-label={t('fileShare.removeNamed', { name })}>
          {t('fileShare.remove')}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
