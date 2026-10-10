import { useQueryClient } from '@tanstack/react-query'
import { Trash2, UserPlus } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { SealedMailKey } from '@kutup/crypto'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { Textarea } from '@kutup/ui/components/textarea'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import {
  groupsKey,
  membershipBody,
  resolveAccount,
  setMembers,
  updateGroup,
  useGroupDetail,
  type GroupRole,
  type MemberInput,
  type PostPolicy,
} from '../groups'

const ROLES: GroupRole[] = ['owner', 'manager', 'member']
const POLICIES: PostPolicy[] = ['anyone', 'local', 'members', 'managers']

/**
 * A group's members and settings (docs/plans/mail-groups.md), for its owners,
 * managers and administrators. Members are added by their Kutup address. For
 * a shared mailbox, saving shares its keys with joining members and makes a
 * new key when anyone leaves, here in the browser.
 */
export function GroupDialog({
  groupId,
  ownKeys,
  administrator,
  onClose,
}: {
  groupId: string
  /** The caller's address keys, to share a shared mailbox's keys from; null when they have none. */
  ownKeys: SealedMailKey[] | null
  /** The caller is an administrator (may change owners and every group). */
  administrator: boolean
  onClose: () => void
}) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const detail = useGroupDetail(groupId)
  const [members, setMembersDraft] = useState<MemberInput[] | null>(null)
  const [displayName, setDisplayName] = useState('')
  const [description, setDescription] = useState('')
  const [postPolicy, setPostPolicy] = useState<PostPolicy>('members')
  const [adding, setAdding] = useState('')
  const [problem, setProblem] = useState<string | null>(null)
  const [withoutHistory, setWithoutHistory] = useState(false)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (!detail.data || members) return
    setMembersDraft(detail.data.members.map(({ userId, address, role, canSendAs }) => ({ userId, address, role, canSendAs })))
    setDisplayName(detail.data.group.displayName)
    setDescription(detail.data.group.description)
    setPostPolicy(detail.data.group.postPolicy)
  }, [detail.data, members])

  const group = detail.data?.group
  const role = group?.myRole
  const canChangeOwners = administrator || role === 'owner'
  const canEdit = administrator || role === 'owner' || role === 'manager'
  const shared = group?.kind === 'shared'
  const system = !!group?.systemRole

  async function add() {
    const address = adding.trim().toLowerCase()
    if (!address || !members) return
    setProblem(null)
    if (members.some((m) => m.address === address)) {
      setAdding('')
      return
    }
    try {
      const account = await resolveAccount(address)
      if (!account) {
        setProblem(t('mailGroups.noAccount', { address }))
        return
      }
      setMembersDraft([...members, { userId: account.userId, address: account.address, role: 'member', canSendAs: false }])
      setAdding('')
    } catch (error) {
      setProblem(apiErrorMessage(error, t('common.tryAgain')))
    }
  }

  async function save(confirmedWithoutHistory: boolean) {
    if (!group || !detail.data || !members) return
    setProblem(null)
    setSaving(true)
    try {
      const policyChanged = postPolicy !== group.postPolicy && !system
      if (displayName.trim() !== group.displayName || description.trim() !== group.description || policyChanged) {
        await updateGroup(group.id, {
          displayName: displayName.trim(),
          description: description.trim(),
          ...(policyChanged ? { postPolicy } : {}),
        })
      }
      const changed =
        members.length !== detail.data.members.length ||
        members.some((m) => {
          const before = detail.data.members.find((c) => c.userId === m.userId)
          return !before || before.role !== m.role || before.canSendAs !== m.canSendAs
        })
      if (changed) {
        const { body, historyShared } = await membershipBody(group, detail.data.members, members, ownKeys)
        if (!historyShared && !confirmedWithoutHistory) {
          setWithoutHistory(true)
          return
        }
        await setMembers(group.id, body)
      }
      void queryClient.invalidateQueries({ queryKey: groupsKey })
      void queryClient.invalidateQueries({ queryKey: ['admin', 'mail', 'groups'] })
      toast.success(t('mailGroups.saved'))
      onClose()
    } catch (error) {
      setProblem(apiErrorMessage(error, t('mailGroups.saveFailed')))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{group ? group.displayName || group.address : t('mailGroups.title')}</DialogTitle>
          <DialogDescription>
            {group ? `${group.address} · ${t(`mailGroups.kind.${group.kind}`)}` : t('mailGroups.loading')}
          </DialogDescription>
        </DialogHeader>
        {detail.isPending || !members ? (
          <Skeleton className="h-40 w-full" />
        ) : detail.isError ? (
          <Alert variant="error">{apiErrorMessage(detail.error, t('common.tryAgain'))}</Alert>
        ) : (
          <div className="max-h-[60vh] space-y-4 overflow-y-auto">
            {detail.data.goesToAdministrators ? <Alert>{t('mailGroups.goesToAdministrators')}</Alert> : null}
            {canEdit ? (
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label={t('mailGroups.displayName')}>
                  {(field) => <Input {...field} value={displayName} maxLength={200} onChange={(e) => setDisplayName(e.target.value)} />}
                </Field>
                <Field label={t('mailGroups.postPolicy')} description={system ? t('mailGroups.systemPolicy') : undefined}>
                  {(field) => (
                    <Select value={postPolicy} onValueChange={(value) => setPostPolicy(value as PostPolicy)} disabled={system}>
                      <SelectTrigger id={field.id} aria-describedby={field['aria-describedby']}>
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
                <Field label={t('mailGroups.description')} className="sm:col-span-2">
                  {(field) => <Textarea {...field} value={description} maxLength={1000} rows={2} onChange={(e) => setDescription(e.target.value)} />}
                </Field>
              </div>
            ) : null}
            <section aria-label={t('mailGroups.members')} className="space-y-2">
              <h3 className="text-sm font-medium">{t('mailGroups.membersCount', { count: members.length })}</h3>
              <ul className="divide-y divide-border rounded-md border border-border">
                {members.map((member) => {
                  const locked = !canEdit || (member.role === 'owner' && !canChangeOwners)
                  return (
                    <li key={member.userId} className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm">
                      <span className="min-w-0 flex-1 truncate">{member.address}</span>
                      <Select
                        value={member.role}
                        disabled={locked}
                        onValueChange={(value) =>
                          setMembersDraft(members.map((m) => (m.userId === member.userId ? { ...m, role: value as GroupRole } : m)))
                        }
                      >
                        <SelectTrigger className="w-32" aria-label={t('mailGroups.roleOf', { address: member.address })}>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {ROLES.filter((r) => r !== 'owner' || canChangeOwners).map((r) => (
                            <SelectItem key={r} value={r}>
                              {t(`mailGroups.role.${r}`)}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      {shared && member.role === 'member' ? (
                        <label className="flex items-center gap-1.5 text-xs">
                          <Checkbox
                            checked={member.canSendAs}
                            disabled={locked}
                            onCheckedChange={(on) =>
                              setMembersDraft(members.map((m) => (m.userId === member.userId ? { ...m, canSendAs: on === true } : m)))
                            }
                          />
                          {t('mailGroups.canSendAs')}
                        </label>
                      ) : null}
                      {canEdit && !locked ? (
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label={t('mailGroups.remove', { address: member.address })}
                          onClick={() => setMembersDraft(members.filter((m) => m.userId !== member.userId))}
                        >
                          <Trash2 />
                        </Button>
                      ) : null}
                    </li>
                  )
                })}
              </ul>
              {canEdit ? (
                <form
                  className="flex gap-2"
                  onSubmit={(e) => {
                    e.preventDefault()
                    void add()
                  }}
                >
                  <Input
                    value={adding}
                    onChange={(e) => setAdding(e.target.value)}
                    placeholder={t('mailGroups.addPlaceholder')}
                    aria-label={t('mailGroups.add')}
                    type="email"
                  />
                  <Button type="submit" variant="outline" disabled={!adding.trim()}>
                    <UserPlus />
                    {t('mailGroups.add')}
                  </Button>
                </form>
              ) : null}
              {shared ? <p className="text-xs text-muted-foreground">{t('mailGroups.sharedKeysHint')}</p> : null}
            </section>
            {withoutHistory ? <Alert variant="warn">{t('mailGroups.withoutHistory')}</Alert> : null}
            {problem ? <Alert variant="error">{problem}</Alert> : null}
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {canEdit ? t('common.cancel') : t('common.close')}
          </Button>
          {canEdit ? (
            <Button loading={saving} onClick={() => void save(withoutHistory)}>
              {withoutHistory ? t('mailGroups.saveWithoutHistory') : t('mailGroups.save')}
            </Button>
          ) : null}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
