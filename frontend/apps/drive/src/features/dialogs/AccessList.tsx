import { Globe, Link2, Server, User } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Avatar } from '@kutup/ui/components/avatar'
import { Button } from '@kutup/ui/components/button'
import { LoadingPanel } from '@kutup/ui/components/states'
import {
  AccessChanged,
  openLinkKey,
  RecipientChanged,
  useFolderAccess,
  useRemoveAccess,
  type FolderAccess,
  type Removal,
} from '@kutup/drive-core/access'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import type { Folder } from '@kutup/drive-core/model'
import { publicLinkUrl } from '@kutup/drive-core/mutations'
import { personOf, usePeople } from '@kutup/drive-core/people'

type Pending = { label: string; removal: Removal } | null

const none: Removal = { members: [], publicLinks: [], federatedShares: [] }

/**
 * Everyone who can open a folder, for its owner: people here, people on
 * other servers, public links. Removing one moves the folder to a new key
 * that they never get (docs/plans/drive-share-revocation.md).
 */
export function AccessList({ folder }: { folder: Folder }) {
  const { t, i18n } = useTranslation()
  const access = useFolderAccess(folder)
  const identity = useDriveIdentity()
  const remove = useRemoveAccess()
  const people = usePeople()
  const [pending, setPending] = useState<Pending>(null)

  if (access.isPending) return <LoadingPanel label={t('dialogs.access.loading')} />
  if (access.isError || !access.data) return <Alert variant="error">{t('dialogs.access.loadFailed')}</Alert>
  const data: FolderAccess = access.data
  const date = (iso: string) => new Date(iso).toLocaleDateString(i18n.language, { dateStyle: 'medium' })
  const permission = (canUpload: boolean) => (canUpload ? t('dialogs.access.canEdit') : t('dialogs.access.canView'))
  const legacyLinks = data.publicLinks.filter((l) => !l.ownerLinkKeyEnvelope).length
  const empty = data.members.length + data.federatedShares.length + data.publicLinks.length === 0

  async function copy(linkId: string) {
    const link = data.publicLinks.find((l) => l.id === linkId)
    if (!link || !identity.data) return
    try {
      await navigator.clipboard.writeText(publicLinkUrl(link.token, await openLinkKey(link, identity.data)))
      toast.success(t('dialogs.access.copied'))
    } catch {
      toast.error(t('common.tryAgain'))
    }
  }

  function confirm() {
    if (!pending) return
    remove.mutate(
      { folder, removed: pending.removal },
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
      : remove.error instanceof RecipientChanged
        ? t('dialogs.access.recipientChanged', { account: remove.error.account })
        : t('dialogs.access.failed')
    : null

  return (
    <section className="space-y-3" aria-label={t('dialogs.access.title')}>
      <h3 className="text-sm font-semibold">{t('dialogs.access.title')}</h3>
      {empty ? <p className="text-sm text-muted-foreground">{t('dialogs.access.empty')}</p> : null}
      <ul className="divide-y divide-border rounded-md border border-border">
        {data.members.map((m) => {
          const person = personOf(people.data, m.account)
          return (
            <Row
              key={m.userId}
              icon={person.profile ? <PersonAvatar {...person} /> : <User className="size-4" aria-hidden />}
              name={person.name}
              detail={person.profile ? `${m.account} · ${permission(m.canUpload)}` : permission(m.canUpload)}
              onRemove={() => setPending({ label: person.name, removal: { ...none, members: [m.userId] } })}
              removeLabel={t('dialogs.access.removeNamed', { name: person.name })}
              busy={remove.isPending}
            />
          )
        })}
        {data.federatedShares.map((f) => {
          const account = `${f.recipientUsername}@${f.recipientServer}`
          const person = personOf(people.data, account)
          return (
            <Row
              key={f.id}
              icon={person.profile ? <PersonAvatar {...person} /> : <Server className="size-4" aria-hidden />}
              name={person.name}
              detail={[person.profile ? account : null, permission(f.canUpload), t('dialogs.access.otherServer')].filter(Boolean).join(' · ')}
              onRemove={() => setPending({ label: person.name, removal: { ...none, federatedShares: [f.id] } })}
              removeLabel={t('dialogs.access.removeNamed', { name: person.name })}
              busy={remove.isPending}
            />
          )
        })}
        {data.publicLinks.map((l) => (
          <Row
            key={l.id}
            icon={l.ownerLinkKeyEnvelope ? <Link2 className="size-4" aria-hidden /> : <Globe className="size-4" aria-hidden />}
            name={t('dialogs.access.link')}
            detail={
              l.expiresAt
                ? t('dialogs.access.linkExpires', { created: date(l.createdAt), expires: date(l.expiresAt) })
                : t('dialogs.access.linkCreated', { created: date(l.createdAt) })
            }
            onCopy={l.ownerLinkKeyEnvelope ? () => void copy(l.id) : undefined}
            onRemove={() =>
              setPending({ label: t('dialogs.access.link'), removal: { ...none, publicLinks: [l.id] } })
            }
            removeLabel={t('dialogs.access.removeLink')}
            busy={remove.isPending}
          />
        ))}
      </ul>
      {legacyLinks > 0 ? <p className="text-xs text-muted-foreground">{t('dialogs.access.legacyLinks', { count: legacyLinks })}</p> : null}
      {pending ? (
        <Alert variant="warn">
          <p className="font-medium">{t('dialogs.access.confirmTitle', { name: pending.label })}</p>
          <p className="mt-1 text-sm">{t('dialogs.access.confirmBody')}</p>
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

export function PersonAvatar({ name, profile }: ReturnType<typeof personOf>) {
  return <Avatar name={name} image={profile?.avatar} contentType={profile?.avatarContentType} size={24} />
}

export function Row({
  icon,
  name,
  detail,
  onCopy,
  onRemove,
  removeLabel,
  busy,
}: {
  icon: ReactNode
  name: string
  detail: string
  onCopy?: () => void
  onRemove: () => void
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
      {onCopy ? (
        <Button size="sm" variant="ghost" onClick={onCopy}>
          {t('dialogs.access.copy')}
        </Button>
      ) : null}
      <Button size="sm" variant="ghost" onClick={onRemove} disabled={busy} aria-label={removeLabel}>
        {t('dialogs.access.remove')}
      </Button>
    </li>
  )
}
