import { useQueryClient } from '@tanstack/react-query'
import { Copy, Link2, Link2Off, UserMinus } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { openLinkKey, useFolderAccess, type AccessLink } from '@kutup/drive-core/access'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import { publicLinkUrl, RecipientNotFound, useCreatePublicLink, useShareFolder } from '@kutup/drive-core/mutations'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { Spinner } from '@kutup/ui/components/states'
import { useRemoveAlbumAccess, type Album } from './albums'

/**
 * Share an album (docs/plans/photos.md): its key sealed to each person's
 * Drive key, as a folder's is. People on this server are found by email;
 * "Can add photos" lets them put their own photos in. People on other
 * servers (`user@server`) view it only, and add it from an invite link.
 * Removing someone moves the album to a new key, with every photo re-sealed
 * under it.
 */
export function ShareAlbumDialog({ album, open, onClose }: { album: Album; open: boolean; onClose: () => void }) {
  const { t, i18n } = useTranslation()
  const queryClient = useQueryClient()
  const identity = useDriveIdentity()
  const access = useFolderAccess(open ? album.folder : undefined)
  const removeAccess = useRemoveAlbumAccess()
  const [email, setEmail] = useState('')
  const [canAdd, setCanAdd] = useState(false)
  const createLink = useCreatePublicLink('photos')
  const [created, setCreated] = useState<string | null>(null)
  useEffect(() => {
    if (open) {
      setEmail('')
      setCanAdd(false)
      setCreated(null)
      setInvite(null)
    }
  }, [open])

  async function copy(url: string) {
    try {
      await navigator.clipboard.writeText(url)
      toast.success(t('share.linkCopied'))
    } catch {
      toast.error(t('share.failed'))
    }
  }

  async function copyLink(link: AccessLink) {
    if (!identity.data) return
    try {
      await copy(publicLinkUrl(link.token, await openLinkKey(link, identity.data), 'photos'))
    } catch {
      toast.error(t('share.failed'))
    }
  }

  const shareFolder = useShareFolder()
  const [invite, setInvite] = useState<{ url: string; account: string } | null>(null)
  function share() {
    setInvite(null)
    shareFolder.mutate(
      {
        folder: album.folder,
        recipient: email.trim(),
        canUpload: canAdd,
        canDelete: false,
        uploadQuotaBytes: null,
        viewOnlyAcrossServers: true,
      },
      {
        onSuccess: (result) => {
          toast.success(t('share.shared', { account: result.account }))
          setEmail('')
          // Someone on another server adds the album from this link.
          if (result.kind === 'federated') setInvite({ url: result.inviteUrl, account: result.account })
          void queryClient.invalidateQueries({ queryKey: ['folder-access', album.id] })
        },
        onError: (error) => toast.error(error instanceof RecipientNotFound ? t('share.notFound') : t('share.failed')),
      },
    )
  }

  const members = access.data?.members ?? []
  const links = access.data?.publicLinks ?? []
  const federated = access.data?.federatedShares ?? []
  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t('share.title', { name: album.name })}</DialogTitle>
          <DialogDescription>{t('share.description')}</DialogDescription>
        </DialogHeader>
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault()
            if (email.trim()) share()
          }}
        >
          <Field label={t('share.email')}>
            {(field) => <Input {...field} type="email" autoComplete="off" value={email} onChange={(e) => setEmail(e.target.value)} />}
          </Field>
          <div className="flex items-center gap-2">
            <Checkbox id="album-can-add" checked={canAdd} onCheckedChange={(v) => setCanAdd(v === true)} />
            <Label htmlFor="album-can-add">{t('share.canAdd')}</Label>
          </div>
          <p className="text-xs text-muted-foreground">{t('share.otherServersHint')}</p>
          <div className="flex justify-end">
            <Button type="submit" disabled={!email.trim() || shareFolder.isPending}>
              {t('share.submit')}
            </Button>
          </div>
        </form>
        <section className="space-y-2 pt-2">
          <h3 className="text-sm font-medium">{t('share.people')}</h3>
          {access.isPending ? <Spinner label={t('share.loading')} /> : null}
          {access.data && members.length + federated.length === 0 ? <p className="text-sm text-muted-foreground">{t('share.nobody')}</p> : null}
          <ul className="divide-y divide-border rounded-lg border border-border empty:hidden">
            {members.map((m) => (
              <li key={m.userId} className="flex items-center gap-2 px-3 py-2">
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm">{m.account}</p>
                  <p className="text-xs text-muted-foreground">{m.canUpload ? t('share.canAddShort') : t('share.viewOnly')}</p>
                </div>
                <Button
                  variant="ghost"
                  size="icon"
                  disabled={removeAccess.isPending}
                  aria-label={t('share.remove', { account: m.account })}
                  onClick={() =>
                    removeAccess.mutate(
                      { album, removed: { members: [m.userId], publicLinks: [], federatedShares: [] } },
                      {
                        onSuccess: () => toast.success(t('share.removed', { account: m.account })),
                        onError: () => toast.error(t('share.failed')),
                      },
                    )
                  }
                >
                  <UserMinus />
                </Button>
              </li>
            ))}
            {federated.map((f) => {
              const account = `${f.recipientUsername}@${f.recipientServer}`
              return (
                <li key={f.id} className="flex items-center gap-2 px-3 py-2">
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm">{account}</p>
                    <p className="text-xs text-muted-foreground">{t('share.otherServer')}</p>
                  </div>
                  <Button
                    variant="ghost"
                    size="icon"
                    disabled={removeAccess.isPending}
                    aria-label={t('share.remove', { account })}
                    onClick={() =>
                      removeAccess.mutate(
                        { album, removed: { members: [], publicLinks: [], federatedShares: [f.id] } },
                        {
                          onSuccess: () => toast.success(t('share.removed', { account })),
                          onError: () => toast.error(t('share.failed')),
                        },
                      )
                    }
                  >
                    <UserMinus />
                  </Button>
                </li>
              )
            })}
          </ul>
          {invite ? (
            <Field label={t('share.inviteLink', { account: invite.account })} description={t('share.inviteHint')}>
              {(field) => (
                <div className="flex gap-2">
                  <Input {...field} readOnly value={invite.url} className="font-mono text-xs" onFocus={(e) => e.currentTarget.select()} />
                  <Button type="button" variant="outline" size="icon" aria-label={t('share.copyInvite')} onClick={() => void copy(invite.url)}>
                    <Copy />
                  </Button>
                </div>
              )}
            </Field>
          ) : null}
        </section>
        <section className="space-y-2 pt-2">
          <div className="flex items-center justify-between gap-2">
            <h3 className="text-sm font-medium">{t('share.links')}</h3>
            <Button
              variant="outline"
              size="sm"
              disabled={createLink.isPending}
              onClick={() =>
                createLink.mutate(album.folder, {
                  onSuccess: (url) => {
                    setCreated(url)
                    void queryClient.invalidateQueries({ queryKey: ['folder-access', album.id] })
                    void copy(url)
                  },
                  onError: () => toast.error(t('share.failed')),
                })
              }
            >
              <Link2 />
              {t('share.createLink')}
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">{t('share.linksHint')}</p>
          {created ? (
            <Field label={t('share.newLink')}>
              {(field) => <Input {...field} readOnly value={created} onFocus={(e) => e.currentTarget.select()} />}
            </Field>
          ) : null}
          {access.data && links.length === 0 ? <p className="text-sm text-muted-foreground">{t('share.noLinks')}</p> : null}
          <ul className="divide-y divide-border rounded-lg border border-border empty:hidden">
            {links.map((link) => (
              <li key={link.id} className="flex items-center gap-2 px-3 py-2">
                <p className="min-w-0 flex-1 truncate text-sm">{t('share.linkMade', { date: new Date(link.createdAt).toLocaleDateString(i18n.language, { dateStyle: 'medium' }) })}</p>
                {link.ownerLinkKeyEnvelope ? (
                  <Button variant="ghost" size="icon" aria-label={t('share.copyLink')} onClick={() => void copyLink(link)}>
                    <Copy />
                  </Button>
                ) : null}
                <Button
                  variant="ghost"
                  size="icon"
                  disabled={removeAccess.isPending}
                  aria-label={t('share.removeLink')}
                  onClick={() =>
                    removeAccess.mutate(
                      { album, removed: { members: [], publicLinks: [link.id], federatedShares: [] } },
                      {
                        onSuccess: () => {
                          setCreated(null)
                          toast.success(t('share.linkRemoved'))
                        },
                        onError: () => toast.error(t('share.failed')),
                      },
                    )
                  }
                >
                  <Link2Off />
                </Button>
              </li>
            ))}
          </ul>
        </section>
      </DialogContent>
    </Dialog>
  )
}
