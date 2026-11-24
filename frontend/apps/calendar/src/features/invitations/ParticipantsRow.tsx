import { useQuery } from '@tanstack/react-query'
import { Trash2 } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { loadAvailability } from '@kutup/calendar-core/busy'
import { canonicalEmail, isAddress } from '@kutup/calendar-core/invitations'
import { ContactSuggestInput } from '@kutup/contacts-core/ui/ContactSuggestInput'
import type { Attendee } from '@kutup/crypto/calendar'
import { Button } from '@kutup/ui/components/button'

/**
 * Proton's participants row (`RowParticipants`, `ParticipantRow`,
 * `BusyParticipantRow`, docs/plans/calendar-e4.md §4): people from
 * Contacts or typed, each required or optional, removed, and, for up to
 * `busyShownMax` of them at once, their busy times around the event.
 */
export function ParticipantsRow({
  participants,
  onChange,
  isOwnAddress,
  max,
  busyShownMax,
  window,
  disabled,
}: {
  participants: Attendee[]
  onChange: (next: Attendee[]) => void
  isOwnAddress: (address: string) => boolean
  max: number
  busyShownMax: number
  /** The event's times (UTC), whose busy blocks are shown. */
  window: { start: string; end: string } | null
  disabled?: boolean
}) {
  const { t } = useTranslation()
  const [value, setValue] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [shown, setShown] = useState<string[]>([])

  const add = (raw: string, name?: string | null) => {
    const email = canonicalEmail(raw)
    if (!email) return
    if (!isAddress(email)) return setError(t('invitations.invalidAddress'))
    if (isOwnAddress(email)) return setError(t('invitations.selfInvitation'))
    if (participants.some((p) => p.email === email)) return setError(t('invitations.already'))
    if (participants.length >= max) return setError(t('invitations.tooMany', { count: max }))
    setError(null)
    setValue('')
    onChange([...participants, { email, name: name?.trim() || null, optional: false }])
  }

  return (
    <div className="space-y-2" data-testid="event-participants">
      {disabled ? null : (
        <div className="flex gap-2">
          <ContactSuggestInput
            id="event-participants-input"
            value={value}
            onValueChange={(v) => {
              setValue(v)
              setError(null)
            }}
            onPick={(match) => add(match.address, match.name)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ',' || e.key === ';') {
                if (value.trim()) {
                  e.preventDefault()
                  add(value)
                }
              }
            }}
            placeholder={t('invitations.addPlaceholder')}
            data-testid="event-participant-input"
          />
          <Button type="button" variant="outline" disabled={!value.trim()} onClick={() => add(value)} data-testid="event-participant-add">
            {t('invitations.add')}
          </Button>
        </div>
      )}
      {error ? (
        <p className="text-xs text-destructive" role="alert">
          {error}
        </p>
      ) : null}
      {participants.length ? (
        <ul className="space-y-1">
          {participants.map((participant) => {
            const showing = shown.includes(participant.email)
            return (
              <li key={participant.email} className="rounded-md border px-2 py-1.5 text-sm" data-testid="event-participant">
                <div className="flex items-center gap-2">
                  <div className="min-w-0 flex-1">
                    <div className="truncate">{participant.name || participant.email}</div>
                    {participant.name ? <div className="truncate text-xs text-muted-foreground">{participant.email}</div> : null}
                    {participant.optional ? <div className="text-xs text-muted-foreground">{t('invitations.optional')}</div> : null}
                  </div>
                  {window ? (
                    <Button
                      type="button"
                      size="sm"
                      variant="ghost"
                      disabled={!showing && shown.length >= busyShownMax}
                      onClick={() => setShown((list) => (showing ? list.filter((e) => e !== participant.email) : [...list, participant.email]))}
                    >
                      {showing ? t('invitations.hideBusy') : t('invitations.showBusy')}
                    </Button>
                  ) : null}
                  {disabled ? null : (
                    <>
                      <Button
                        type="button"
                        size="sm"
                        variant="ghost"
                        onClick={() => onChange(participants.map((p) => (p.email === participant.email ? { ...p, optional: !p.optional } : p)))}
                        data-testid="event-participant-optional"
                      >
                        {participant.optional ? t('invitations.makeRequired') : t('invitations.makeOptional')}
                      </Button>
                      <Button
                        type="button"
                        size="icon"
                        variant="ghost"
                        aria-label={t('invitations.remove', { email: participant.email })}
                        onClick={() => onChange(participants.filter((p) => p.email !== participant.email))}
                        data-testid="event-participant-remove"
                      >
                        <Trash2 className="size-4" />
                      </Button>
                    </>
                  )}
                </div>
                {showing && window ? <BusyLine email={participant.email} window={window} /> : null}
              </li>
            )
          })}
        </ul>
      ) : null}
    </div>
  )
}

/** A participant's busy times on the event's day, Proton's `BusyParticipantRow`. */
function BusyLine({ email, window }: { email: string; window: { start: string; end: string } }) {
  const { t, i18n } = useTranslation()
  // The whole day around the event (in UTC), as the row shows it.
  const day = new Date(window.start)
  const from = new Date(Date.UTC(day.getUTCFullYear(), day.getUTCMonth(), day.getUTCDate())).toISOString()
  const to = new Date(Math.max(Date.parse(from) + 24 * 3600 * 1000, Date.parse(window.end))).toISOString()
  const busy = useQuery({
    queryKey: ['calendar', 'busy', email, from, to],
    queryFn: () => loadAvailability(email, from, to),
    staleTime: 60_000,
  })
  if (busy.isPending) return <p className="mt-1 text-xs text-muted-foreground">{t('common.loading')}</p>
  if (busy.isError || !busy.data.accessible) return <p className="mt-1 text-xs text-muted-foreground">{t('invitations.availabilityUnknown')}</p>
  const clash = busy.data.busy.some((b) => Date.parse(b.startUtc) < Date.parse(window.end) && Date.parse(b.endUtc) > Date.parse(window.start))
  const time = new Intl.DateTimeFormat(i18n.language, { timeStyle: 'short' })
  return (
    <div className="mt-1 text-xs" data-testid="event-participant-busy">
      <p className={clash ? 'text-destructive' : 'text-muted-foreground'}>{clash ? t('invitations.busyThen') : t('invitations.freeThen')}</p>
      {busy.data.busy.length ? (
        <ul className="text-muted-foreground">
          {busy.data.busy.map((b) => (
            <li key={b.startUtc}>{b.fullDay ? t('invitations.busyAllDay') : `${time.format(new Date(b.startUtc))} – ${time.format(new Date(b.endUtc))}`}</li>
          ))}
        </ul>
      ) : null}
    </div>
  )
}
