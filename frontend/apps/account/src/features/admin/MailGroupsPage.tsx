import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Settings2, Trash2, Users } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useMailAccount } from '@kutup/mail-core/api'
import { newGroupKey, resolveAccount, type AccountRef, type GroupKind, type MailGroup, type PostPolicy } from '@kutup/mail-core/groups'
import { GroupDialog } from '@kutup/mail-core/ui/GroupDialog'
import api from '@kutup/session/client'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@kutup/ui/components/table'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { formatBytes } from '@kutup/ui/lib/format'
import { adminKey } from './api'

// Mail groups for administrators (docs/plans/mail-groups.md): every group,
// the role addresses first; creating lists and shared mailboxes (a shared
// mailbox's first key is made here, in this browser, for its owners); quotas;
// members through the same dialog owners use.

const groupsAdminKey = [...adminKey, 'mail', 'groups'] as const
const GIB = 1024 * 1024 * 1024
const POLICIES: PostPolicy[] = ['anyone', 'local', 'members', 'managers']

function useServerName() {
  return useQuery({
    queryKey: ['auth-settings', 'server-name'],
    staleTime: Infinity,
    queryFn: async () => (await api.get<{ chat?: { serverName?: string } }>('/auth/settings')).data.chat?.serverName ?? '',
  })
}

export function MailGroupsPage() {
  const { t, i18n } = useTranslation()
  const queryClient = useQueryClient()
  const account = useMailAccount()
  const groups = useQuery({
    queryKey: groupsAdminKey,
    queryFn: async () => (await api.get<MailGroup[]>('/admin/mail/groups')).data,
  })
  const [creating, setCreating] = useState(false)
  const [managing, setManaging] = useState<string | null>(null)
  const [quotaOf, setQuotaOf] = useState<MailGroup | null>(null)
  const [deleting, setDeleting] = useState<MailGroup | null>(null)
  const remove = useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/admin/mail/groups/${id}`)
    },
    onSuccess: () => {
      toast.success(t('mailGroups.deleted'))
      setDeleting(null)
      void queryClient.invalidateQueries({ queryKey: groupsAdminKey })
    },
  })
  const ownKeys = account.data ? [account.data.key, ...account.data.olderKeys] : null

  return (
    <PageBody>
      <PageHeader
        title={t('admin.mailGroups.title')}
        description={t('admin.mailGroups.description')}
        actions={
          <Button onClick={() => setCreating(true)}>
            <Plus />
            {t('admin.mailGroups.create')}
          </Button>
        }
      />
      {groups.isPending ? (
        <LoadingPanel label={t('common.loading')} />
      ) : groups.isError ? (
        <Alert variant="error">{apiErrorMessage(groups.error, t('common.tryAgain'))}</Alert>
      ) : groups.data.length === 0 ? (
        <EmptyState title={t('admin.mailGroups.emptyTitle')} description={t('admin.mailGroups.emptyDescription')} />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t('admin.mailGroups.address')}</TableHead>
              <TableHead>{t('admin.mailGroups.kind')}</TableHead>
              <TableHead>{t('admin.mailGroups.members')}</TableHead>
              <TableHead>{t('admin.mailGroups.storage')}</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {groups.data.map((group) => (
              <TableRow key={group.id}>
                <TableCell>
                  <span className="block font-medium">{group.displayName || group.address}</span>
                  <span className="block text-xs text-muted-foreground">
                    {group.address}
                    {group.systemRole ? ` · ${t(`admin.mailGroups.role.${group.systemRole}`)}` : ''}
                  </span>
                </TableCell>
                <TableCell>
                  <Badge variant="neutral">{t(`mailGroups.kind.${group.kind}`)}</Badge>
                </TableCell>
                <TableCell className="text-sm">
                  {group.systemRole && group.memberCount === 0 ? t('mailGroups.toAdministrators') : t('mailGroups.membersCount', { count: group.memberCount })}
                </TableCell>
                <TableCell className="text-sm tabular-nums">
                  {formatBytes(group.storageUsedBytes, i18n.language)} / {formatBytes(group.storageQuotaBytes, i18n.language)}
                </TableCell>
                <TableCell className="whitespace-nowrap text-right">
                  <Button size="sm" variant="ghost" onClick={() => setManaging(group.id)}>
                    <Users />
                    {t('mailGroups.manage')}
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => setQuotaOf(group)}>
                    <Settings2 />
                    {t('admin.mailGroups.quota')}
                  </Button>
                  {group.systemRole ? null : (
                    <Button size="icon" variant="ghost" aria-label={t('admin.mailGroups.deleteOne', { address: group.address })} onClick={() => setDeleting(group)}>
                      <Trash2 />
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      {creating ? <CreateGroupDialog onClose={() => setCreating(false)} /> : null}
      {managing ? (
        <GroupDialog
          groupId={managing}
          ownKeys={ownKeys}
          administrator
          onClose={() => {
            setManaging(null)
            void queryClient.invalidateQueries({ queryKey: groupsAdminKey })
          }}
        />
      ) : null}
      {quotaOf ? <QuotaDialog group={quotaOf} onClose={() => setQuotaOf(null)} /> : null}
      <ConfirmDestructive
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={t('admin.mailGroups.deleteTitle', { address: deleting?.address ?? '' })}
        description={deleting?.kind === 'shared' ? t('admin.mailGroups.deleteShared') : t('admin.mailGroups.deleteList')}
        submit={t('admin.mailGroups.delete')}
        pending={remove.isPending}
        error={remove.error}
        errorFallback={t('common.tryAgain')}
        onConfirm={() => deleting && remove.mutate(deleting.id)}
      />
    </PageBody>
  )
}

function QuotaDialog({ group, onClose }: { group: MailGroup; onClose: () => void }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [gib, setGib] = useState(String(Math.max(1, Math.round(group.storageQuotaBytes / GIB))))
  const save = useMutation({
    mutationFn: async () => {
      await api.patch(`/admin/mail/groups/${group.id}`, { storageQuotaBytes: Math.round(Number(gib) * GIB) })
    },
    onSuccess: () => {
      toast.success(t('mailGroups.saved'))
      void queryClient.invalidateQueries({ queryKey: groupsAdminKey })
      onClose()
    },
  })
  const valid = Number(gib) > 0 && Number(gib) <= 100_000
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('admin.mailGroups.quotaTitle', { address: group.address })}</DialogTitle>
          <DialogDescription>{t('admin.mailGroups.quotaDescription')}</DialogDescription>
        </DialogHeader>
        <Field label={t('admin.mailGroups.quotaGib')}>
          {(field) => <Input {...field} inputMode="decimal" value={gib} onChange={(e) => setGib(e.target.value)} />}
        </Field>
        {save.isError ? <Alert variant="error">{apiErrorMessage(save.error, t('common.tryAgain'))}</Alert> : null}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button disabled={!valid} loading={save.isPending} onClick={() => save.mutate()}>
            {t('common.save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function CreateGroupDialog({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const server = useServerName()
  const [name, setName] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [kind, setKind] = useState<GroupKind>('list')
  const [postPolicy, setPostPolicy] = useState<PostPolicy>('members')
  const [gib, setGib] = useState('5')
  const [ownerText, setOwnerText] = useState('')
  const [owners, setOwners] = useState<AccountRef[]>([])
  const [problem, setProblem] = useState<string | null>(null)
  const create = useMutation({
    mutationFn: async () => {
      const lower = name.trim().toLowerCase()
      const groupKey = kind === 'shared' ? await newGroupKey(`${lower}@${server.data}`, owners) : undefined
      await api.post('/admin/mail/groups', {
        name: lower,
        displayName: displayName.trim(),
        kind,
        postPolicy,
        storageQuotaBytes: Math.round(Number(gib) * GIB),
        owners: owners.map((owner) => owner.userId),
        ...(groupKey ? { groupKey } : {}),
      })
    },
    onSuccess: () => {
      toast.success(t('admin.mailGroups.created'))
      void queryClient.invalidateQueries({ queryKey: groupsAdminKey })
      onClose()
    },
    onError: (error) => setProblem(apiErrorMessage(error, t('admin.mailGroups.createFailed'))),
  })

  async function addOwner() {
    const address = ownerText.trim().toLowerCase()
    if (!address) return
    setProblem(null)
    const account = await resolveAccount(address).catch(() => null)
    if (!account) {
      setProblem(t('mailGroups.noAccount', { address }))
      return
    }
    if (!owners.some((owner) => owner.userId === account.userId)) setOwners([...owners, account])
    setOwnerText('')
  }

  const valid = /^[a-z0-9_-]{3,32}$/.test(name.trim().toLowerCase()) && owners.length > 0 && Number(gib) > 0 && !!server.data
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>{t('admin.mailGroups.createTitle')}</DialogTitle>
          <DialogDescription>{t('admin.mailGroups.createDescription')}</DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            if (valid) create.mutate()
          }}
        >
          <Field label={t('admin.mailGroups.name')} description={server.data ? t('admin.mailGroups.nameHint', { address: `${name.trim().toLowerCase() || 'team'}@${server.data}` }) : undefined}>
            {(field) => <Input {...field} value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" />}
          </Field>
          <Field label={t('mailGroups.displayName')}>
            {(field) => <Input {...field} value={displayName} maxLength={200} onChange={(e) => setDisplayName(e.target.value)} />}
          </Field>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label={t('admin.mailGroups.kind')}>
              {(field) => (
                <Select value={kind} onValueChange={(value) => setKind(value as GroupKind)}>
                  <SelectTrigger id={field.id}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="list">{t('mailGroups.kind.list')}</SelectItem>
                    <SelectItem value="shared">{t('mailGroups.kind.shared')}</SelectItem>
                  </SelectContent>
                </Select>
              )}
            </Field>
            <Field label={t('mailGroups.postPolicy')}>
              {(field) => (
                <Select value={postPolicy} onValueChange={(value) => setPostPolicy(value as PostPolicy)}>
                  <SelectTrigger id={field.id}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {POLICIES.map((policy) => (
                      <SelectItem key={policy} value={policy}>
                        {t(`mailGroups.policy.${policy}`)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </Field>
          </div>
          <p className="text-xs text-muted-foreground">{t(`admin.mailGroups.kindHint.${kind}`)}</p>
          <Field label={t('admin.mailGroups.quotaGib')}>
            {(field) => <Input {...field} inputMode="decimal" value={gib} onChange={(e) => setGib(e.target.value)} />}
          </Field>
          <div className="space-y-2">
            <p className="text-sm font-medium">{t('admin.mailGroups.owners')}</p>
            {owners.length > 0 ? (
              <ul className="flex flex-wrap gap-1">
                {owners.map((owner) => (
                  <li key={owner.userId}>
                    <Badge variant="neutral">
                      {owner.address}
                      <button
                        type="button"
                        className="ml-1"
                        aria-label={t('mailGroups.remove', { address: owner.address })}
                        onClick={() => setOwners(owners.filter((o) => o.userId !== owner.userId))}
                      >
                        ×
                      </button>
                    </Badge>
                  </li>
                ))}
              </ul>
            ) : null}
            <div className="flex gap-2">
              <Input
                type="email"
                value={ownerText}
                onChange={(e) => setOwnerText(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault()
                    void addOwner()
                  }
                }}
                placeholder={t('mailGroups.addPlaceholder')}
                aria-label={t('admin.mailGroups.addOwner')}
              />
              <Button type="button" variant="outline" onClick={() => void addOwner()} disabled={!ownerText.trim()}>
                {t('admin.mailGroups.addOwner')}
              </Button>
            </div>
          </div>
          {problem ? <Alert variant="error">{problem}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={!valid} loading={create.isPending}>
              {t('admin.mailGroups.create')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
