import { Check, Mail, ShieldAlert } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useQuery } from '@tanstack/react-query'
import { CALENDAR_COLORS, useCalendarMutation, type OwnerIdentityChanged } from '@kutup/calendar-core/api'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { acceptInvitation, declineInvitation, loadInvitations, openInvitation, PersonNotConfirmed, trustOwner, type ReceivedInvitationRow } from './client'

/**
 * "Shared with you" in the sidebar (Proton's `SharedCalendarsSection` and
 * its invitation modal): each pending invitation, by its owner, opened
 * before it is joined.
 */
export function SharedWithYou({ ownerChanged }: { ownerChanged: OwnerIdentityChanged[] }) {
  const { t } = useTranslation()
  const invitations = useQuery({ queryKey: ['calendar', 'invitations'], queryFn: loadInvitations })
  const [opening, setOpening] = useState<ReceivedInvitationRow | null>(null)
  const list = invitations.data ?? []
  // An invitation being opened stays open while the list reloads under it.
  if (!list.length && !ownerChanged.length && !opening) return null
  return (
    <>
      <li className="px-3 pb-1 pt-3 text-[11px] font-medium uppercase tracking-wider text-chrome-muted">{t('sharing.invitations.title')}</li>
      {ownerChanged.map((changed) => (
        <OwnerChangedRow key={changed.calendarId} changed={changed} />
      ))}
      {list.map((invitation) => (
        <li key={invitation.id}>
          <button
            type="button"
            onClick={() => setOpening(invitation)}
            className="flex w-full items-center gap-3 rounded-md px-3 py-1.5 text-left text-sm hover:bg-chrome-accent/60"
            data-testid="calendar-invitation"
          >
            <Mail className="size-4 shrink-0 text-chrome-muted" aria-hidden />
            <span className="min-w-0 flex-1 truncate">{t('sharing.invitations.from', { address: invitation.owner.address })}</span>
          </button>
        </li>
      ))}
      {opening ? <InvitationDialog invitation={opening} onClose={() => setOpening(null)} /> : null}
    </>
  )
}

/** A calendar whose owner's identity changed: closed, until the user trusts the new one. */
function OwnerChangedRow({ changed }: { changed: OwnerIdentityChanged }) {
  const { t } = useTranslation()
  const me = useDriveIdentity()
  const [open, setOpen] = useState(false)
  const trust = useCalendarMutation(() => trustOwner(me.data!, changed.ownerAddress))
  return (
    <li>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="flex w-full items-center gap-3 rounded-md px-3 py-1.5 text-left text-sm text-destructive hover:bg-chrome-accent/60"
      >
        <ShieldAlert className="size-4 shrink-0" aria-hidden />
        <span className="min-w-0 flex-1 truncate">{t('sharing.ownerChanged.row', { address: changed.ownerAddress })}</span>
      </button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('sharing.ownerChanged.title', { address: changed.ownerAddress })}</DialogTitle>
            <DialogDescription>{t('sharing.ownerChanged.body', { address: changed.ownerAddress })}</DialogDescription>
          </DialogHeader>
          {trust.error ? <Alert variant="error">{apiErrorMessage(trust.error, t('sharing.errors.saveFailed'))}</Alert> : null}
          <DialogFooter>
            <Button variant="ghost" onClick={() => setOpen(false)}>
              {t('sharing.ownerChanged.keepClosed')}
            </Button>
            <Button
              variant="destructive"
              loading={trust.isPending}
              disabled={!me.data}
              onClick={() =>
                // The mutation reloads the calendars, which opens this one now.
                trust.mutate(undefined, { onSuccess: () => setOpen(false) })
              }
            >
              {t('sharing.ownerChanged.trust')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </li>
  )
}

/** Proton's `ShareCalendarInvitationModal`: the calendar opened, its owner checked; join or decline. */
function InvitationDialog({ invitation, onClose }: { invitation: ReceivedInvitationRow; onClose: () => void }) {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const me = useDriveIdentity()
  const [confirmed, setConfirmed] = useState(false)
  const [color, setColor] = useState<string>(CALENDAR_COLORS[0])
  const opened = useQuery({
    queryKey: ['calendar', 'invitation', invitation.id, confirmed],
    enabled: !!me.data,
    retry: false,
    queryFn: () => openInvitation(session, me.data!, invitation, confirmed),
  })
  const join = useCalendarMutation(() => acceptInvitation(session, me.data!, invitation, color, confirmed))
  const decline = useCalendarMutation(() => declineInvitation(invitation.id))
  const doubt = opened.error instanceof PersonNotConfirmed ? opened.error : null
  const busy = join.isPending || decline.isPending

  return (
    <Dialog open onOpenChange={(o) => !o && !busy && onClose()}>
      <DialogContent data-testid="invitation-dialog">
        <DialogHeader>
          <DialogTitle>{opened.data ? t('sharing.invitations.joinTitle', { name: opened.data.name }) : t('sharing.invitations.title')}</DialogTitle>
          <DialogDescription>{t('sharing.invitations.fromLong', { address: invitation.owner.address })}</DialogDescription>
        </DialogHeader>
        {opened.isPending && !doubt ? <p className="text-sm text-muted-foreground">{t('common.loading')}</p> : null}
        {doubt ? (
          <Alert variant="error" title={t(`sharing.invitations.doubt.${doubt.status.kind}.title`, { address: doubt.address })}>
            <p>{t(`sharing.invitations.doubt.${doubt.status.kind}.body`, { address: doubt.address })}</p>
            <Button className="mt-2" size="sm" variant="outline" onClick={() => setConfirmed(true)} data-testid="invitation-open-anyway">
              {t('sharing.invitations.openAnyway')}
            </Button>
          </Alert>
        ) : opened.isError ? (
          <Alert variant="error">{apiErrorMessage(opened.error, t('sharing.invitations.unreadable'))}</Alert>
        ) : null}
        {opened.data ? (
          <div className="space-y-4">
            {opened.data.description ? <p className="text-sm">{opened.data.description}</p> : null}
            <p className="text-sm">{opened.data.preset ? t(`sharing.invitations.preset.${opened.data.preset}`) : t('sharing.preset.other')}</p>
            <fieldset className="space-y-2">
              <legend className="text-sm font-medium">{t('sharing.invitations.color')}</legend>
              <div className="flex flex-wrap gap-2">
                {CALENDAR_COLORS.map((option) => (
                  <button
                    key={option}
                    type="button"
                    onClick={() => setColor(option)}
                    aria-label={option}
                    aria-pressed={color === option}
                    className={cn('grid size-8 place-items-center rounded-full text-white ring-offset-2 ring-offset-background', color === option && 'ring-2 ring-ring')}
                    style={{ background: option }}
                  >
                    {color === option ? <Check className="size-4" aria-hidden /> : null}
                  </button>
                ))}
              </div>
            </fieldset>
          </div>
        ) : null}
        {join.error || decline.error ? <Alert variant="error">{apiErrorMessage(join.error ?? decline.error, t('sharing.errors.saveFailed'))}</Alert> : null}
        <DialogFooter>
          <Button
            variant="ghost"
            loading={decline.isPending}
            disabled={busy}
            onClick={() =>
              decline.mutate(undefined, {
                onSuccess: () => {
                  toast.success(t('sharing.invitations.declined'))
                  onClose()
                },
              })
            }
            data-testid="invitation-decline"
          >
            {t('sharing.invitations.decline')}
          </Button>
          <Button
            loading={join.isPending}
            disabled={busy || !opened.data}
            onClick={() =>
              join.mutate(undefined, {
                onSuccess: () => {
                  toast.success(t('sharing.invitations.joined', { name: opened.data?.name ?? '' }))
                  onClose()
                },
              })
            }
            data-testid="invitation-join"
          >
            {t('sharing.invitations.join')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
