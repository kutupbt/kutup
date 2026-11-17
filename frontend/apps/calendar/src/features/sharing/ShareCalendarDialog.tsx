import { UserPlus, X } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useQuery } from '@tanstack/react-query'
import { useCalendarMutation, type Calendar } from '@kutup/calendar-core/api'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import { IdentityShareWarning } from '@kutup/drive-ui/IdentityWarning'
import { useMailAccount } from '@kutup/mail-core/api'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@kutup/ui/components/tabs'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import {
  IdentityNotConfirmed,
  invite,
  loadSharing,
  presetOf,
  removeMember,
  revokeInvitation,
  setMemberPreset,
  type MemberRow,
  type Preset,
  type SentInvitationRow,
} from './client'
import { inviteErrorText } from './errorText'
import { LinksPanel } from './LinksPanel'

function PresetSelect({ value, onChange, label, disabled }: { value: Preset; onChange: (preset: Preset) => void; label: string; disabled?: boolean }) {
  const { t } = useTranslation()
  return (
    <Select value={value} onValueChange={(v) => onChange(v as Preset)} disabled={disabled}>
      <SelectTrigger className="w-52" aria-label={label}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="edit">{t('sharing.preset.edit')}</SelectItem>
        <SelectItem value="view">{t('sharing.preset.view')}</SelectItem>
      </SelectContent>
    </Select>
  )
}

/** Proton's `ShareCalendarModal` and the share section of its calendar settings: people, then links. */
export function ShareCalendarDialog({ calendar, open, onOpenChange }: { calendar: Calendar; open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation()
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl" data-testid="calendar-share">
        <DialogHeader>
          <DialogTitle>{t('sharing.title', { name: calendar.name })}</DialogTitle>
          <DialogDescription>{t('sharing.description')}</DialogDescription>
        </DialogHeader>
        <Tabs defaultValue="people">
          <TabsList>
            <TabsTrigger value="people">{t('sharing.tabs.people')}</TabsTrigger>
            <TabsTrigger value="links">{t('sharing.tabs.links')}</TabsTrigger>
          </TabsList>
          <TabsContent value="people">{open ? <PeoplePanel calendar={calendar} /> : null}</TabsContent>
          <TabsContent value="links">{open ? <LinksPanel calendar={calendar} /> : null}</TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  )
}

function PeoplePanel({ calendar }: { calendar: Calendar }) {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const me = useDriveIdentity()
  const account = useMailAccount()
  const sharing = useQuery({ queryKey: ['calendar', 'sharing', calendar.id], queryFn: () => loadSharing(calendar.id) })
  const [address, setAddress] = useState('')
  const [preset, setPreset] = useState<Preset>('view')
  const [removing, setRemoving] = useState<MemberRow | null>(null)
  const [confirmed, setConfirmed] = useState<Set<string>>(new Set())

  const add = useCalendarMutation((confirm: boolean) => invite(session, me.data!, calendar, address, preset, confirm))
  const change = useCalendarMutation((v: { member: MemberRow; preset: Preset }) => setMemberPreset(calendar.id, v.member.accountId, v.preset))
  const revoke = useCalendarMutation((invitation: SentInvitationRow) => revokeInvitation(calendar.id, invitation.id))
  const remove = useCalendarMutation((v: { member: MemberRow; confirmed: Set<string> }) => removeMember(session, me.data!, account.data!, calendar, v.member.accountId, v.confirmed))

  function submit(confirm: boolean) {
    if (!address.trim() || !me.data) return
    add.mutate(confirm, {
      onSuccess: () => {
        toast.success(t('sharing.invited', { address: address.trim() }))
        setAddress('')
      },
    })
  }

  function doRemove(member: MemberRow, people: Set<string>) {
    remove.mutate(
      { member, confirmed: people },
      {
        onSuccess: () => {
          setRemoving(null)
          setConfirmed(new Set())
          toast.success(t('sharing.removed', { address: member.address }))
        },
      },
    )
  }

  // A person who stays whose identity changed: their account, to confirm.
  const doubtful = remove.error instanceof IdentityNotConfirmed ? remove.error : null
  const doubtfulAccount = doubtful ? (sharing.data?.members.find((m) => m.address === doubtful.account) ?? sharing.data?.invitations.find((i) => i.address === doubtful.account))?.accountId : undefined
  const pending = (sharing.data?.invitations ?? []).filter((i) => i.state === 'pending' || i.state === 'declined')

  return (
    <div className="mt-4 space-y-5">
      <form
        className="space-y-2"
        onSubmit={(e) => {
          e.preventDefault()
          submit(false)
        }}
      >
        <Label htmlFor="share-address">{t('sharing.addPeople')}</Label>
        <div className="flex flex-wrap gap-2">
          <Input
            id="share-address"
            className="min-w-48 flex-1"
            type="email"
            autoComplete="off"
            placeholder={t('sharing.addressPlaceholder')}
            value={address}
            onChange={(e) => {
              setAddress(e.target.value)
              add.reset()
            }}
            data-testid="share-address"
          />
          <PresetSelect value={preset} onChange={setPreset} label={t('sharing.presetLabel')} />
          <Button type="submit" loading={add.isPending} disabled={!address.trim() || !me.data} data-testid="share-invite">
            <UserPlus />
            {t('sharing.share')}
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">{t('sharing.presetHint')}</p>
        {add.error instanceof IdentityNotConfirmed ? (
          <IdentityShareWarning error={add.error} onShareAnyway={() => submit(true)} />
        ) : add.error ? (
          <Alert variant="error">{inviteErrorText(add.error, t)}</Alert>
        ) : null}
      </form>

      <section aria-labelledby="share-members" className="space-y-2">
        <h3 id="share-members" className="text-sm font-medium">
          {t('sharing.members')}
        </h3>
        {sharing.isPending ? (
          <p className="text-sm text-muted-foreground">{t('common.loading')}</p>
        ) : sharing.isError ? (
          <Alert variant="error">{apiErrorMessage(sharing.error, t('sharing.errors.loadFailed'))}</Alert>
        ) : !sharing.data.members.length && !pending.length ? (
          <p className="text-sm text-muted-foreground">{t('sharing.nobody')}</p>
        ) : (
          <ul className="divide-y divide-border rounded-md border border-border" data-testid="share-members">
            {sharing.data.members.map((member) => {
              const current = presetOf(member.permissions)
              return (
                <li key={member.accountId} className="flex flex-wrap items-center gap-2 px-3 py-2">
                  <span className="min-w-0 flex-1 truncate text-sm">{member.address}</span>
                  {current ? (
                    <PresetSelect
                      value={current}
                      label={t('sharing.presetOf', { address: member.address })}
                      disabled={change.isPending}
                      onChange={(next) =>
                        change.mutate(
                          { member, preset: next },
                          {
                            onSuccess: () => toast.success(t('sharing.presetChanged', { address: member.address })),
                            onError: (e) => toast.error(apiErrorMessage(e, t('sharing.errors.saveFailed'))),
                          },
                        )
                      }
                    />
                  ) : (
                    <span className="text-xs text-muted-foreground">{t('sharing.preset.other')}</span>
                  )}
                  <Button variant="ghost" size="icon" className="size-8" aria-label={t('sharing.remove', { address: member.address })} onClick={() => setRemoving(member)}>
                    <X />
                  </Button>
                </li>
              )
            })}
            {pending.map((invitation) => (
              <li key={invitation.id} className="flex flex-wrap items-center gap-2 px-3 py-2">
                <span className="min-w-0 flex-1 truncate text-sm">{invitation.address}</span>
                <span className="text-xs text-muted-foreground">{t(invitation.state === 'declined' ? 'sharing.status.declined' : 'sharing.status.sent')}</span>
                <span className="text-xs text-muted-foreground">{presetOf(invitation.permissions) ? t(`sharing.preset.${presetOf(invitation.permissions)}`) : t('sharing.preset.other')}</span>
                <Button
                  variant="ghost"
                  size="icon"
                  className="size-8"
                  aria-label={t(invitation.state === 'declined' ? 'sharing.deleteInvitation' : 'sharing.revoke', { address: invitation.address })}
                  disabled={revoke.isPending}
                  onClick={() =>
                    revoke.mutate(invitation, {
                      onSuccess: () => toast.success(t(invitation.state === 'declined' ? 'sharing.invitationDeleted' : 'sharing.revoked')),
                      onError: (e) => toast.error(apiErrorMessage(e, t('sharing.errors.saveFailed'))),
                    })
                  }
                >
                  <X />
                </Button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <ConfirmDestructive
        open={removing !== null}
        onOpenChange={(o) => {
          if (!o) {
            setRemoving(null)
            setConfirmed(new Set())
            remove.reset()
          }
        }}
        title={t('sharing.removeTitle', { address: removing?.address ?? '' })}
        description={t('sharing.removeDescription')}
        blocked={
          doubtful && doubtfulAccount ? (
            <div className="space-y-2">
              <p>{t(`sharing.removeDoubt.${doubtful.status.kind}`, { address: doubtful.account })}</p>
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  const next = new Set(confirmed).add(doubtfulAccount)
                  setConfirmed(next)
                  if (removing) doRemove(removing, next)
                }}
                data-testid="share-remove-anyway"
              >
                {t('sharing.removeAnyway')}
              </Button>
            </div>
          ) : undefined
        }
        submit={t('sharing.removeSubmit')}
        pending={remove.isPending}
        error={doubtful ? undefined : remove.error}
        errorFallback={t('sharing.errors.removeFailed')}
        onConfirm={() => removing && doRemove(removing, confirmed)}
      />
    </div>
  )
}
