import { useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { EventRefusedError, PERMISSION, deleteEvent, loadSeries, useCalendarMutation, useCalendars } from '@kutup/calendar-core/api'
import { useMailAccount } from '@kutup/mail-core/api'
import { useRequiredSession } from '@kutup/session/store'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { isRecurring, setDeleteRequest, useDeleteRequest, type DeleteRequest } from './deleteState'
import { choicesFor, planDelete, seriesContext, type RecurringType, type SeriesContext } from './recurrence/actions'
import { RecurringDialog } from './recurrence/RecurringDialog'
import { planOf, runPlan, type Plan } from './recurrence/run'

// Deleting an event, from the editor or the event's popover (Proton's
// `handleDeleteEvent`): one that doesn't repeat after a confirmation, a
// repeating one through "this event / this and future events / all events".

/** The confirmations a delete goes through; rendered once in the app's frame. */
export function EventDeleteFlow() {
  const { t } = useTranslation()
  const request = useDeleteRequest()
  const session = useRequiredSession()
  const account = useMailAccount()
  const calendars = useCalendars()
  const queryClient = useQueryClient()
  const [confirming, setConfirming] = useState(false)
  const [series, setSeries] = useState<{ types: RecurringType[]; context: SeriesContext } | null>(null)
  const plan = useRef<{ type: RecurringType; plan: Plan } | null>(null)
  const event = request?.event
  const calendar = (calendars.data?.calendars ?? []).find((c) => c.id === event?.calendarId && (c.permissions & PERMISSION.write) !== 0)

  const finish = (text: string) => {
    const done = request?.onDone
    setConfirming(false)
    setSeries(null)
    plan.current = null
    setDeleteRequest(null)
    void queryClient.invalidateQueries({ queryKey: ['calendar'] })
    toast.success(text)
    done?.()
  }
  const cancel = () => {
    setConfirming(false)
    setSeries(null)
    plan.current = null
    setDeleteRequest(null)
  }

  // Proton's: every event of the series read first, then the choice.
  const ask = useCalendarMutation(async (target: DeleteRequest) => {
    if (!account.data || !calendar) throw new Error('no calendar')
    if (!isRecurring(target.event)) return null
    const context = await seriesContext(await loadSeries(account.data, calendar, target.event.fields.uid), target.event, target.instance)
    return context ? { types: await choicesFor(context), context } : null
  })
  useEffect(() => {
    if (!request) return
    ask.reset()
    remove.reset()
    run.reset()
    ask.mutate(request, {
      onSuccess: (asked) => (asked ? setSeries(asked) : setConfirming(true)),
      onError: (error) => {
        toast.error(apiErrorMessage(error, t('events.saveFailed')))
        setDeleteRequest(null)
      },
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps -- once per request
  }, [request])

  const remove = useCalendarMutation(async () => {
    if (!account.data || !calendar || !event) throw new Error('no calendar')
    await deleteEvent(session, account.data, calendar, event)
  })
  const run = useCalendarMutation(async (type: RecurringType) => {
    if (!account.data || !calendar || !series) throw new Error('no calendar')
    if (!plan.current || plan.current.type !== type) plan.current = { type, plan: planOf(await planDelete(type, series.context)) }
    await runPlan(plan.current.plan, session, account.data, calendar)
    return type
  })
  const errorText = (error: unknown) =>
    error instanceof EventRefusedError && error.code === 'revisionConflict' ? t('events.changedElsewhere') : error ? apiErrorMessage(error, t('events.saveFailed')) : null
  const doneText: Record<RecurringType, string> = { single: t('events.deleted'), future: t('recurrence.futureDeleted'), all: t('recurrence.allDeleted') }

  return (
    <>
      <RecurringDialog
        mode="delete"
        types={series?.types ?? null}
        pending={run.isPending}
        error={errorText(run.error)}
        onConfirm={(type) => run.mutate(type, { onSuccess: (done) => finish(doneText[done]) })}
        onClose={cancel}
      />
      {event ? (
        <ConfirmDestructive
          open={confirming}
          onOpenChange={(open) => (open ? setConfirming(true) : cancel())}
          title={t('events.deleteTitle', { name: event.fields.summary ?? t('events.untitled') })}
          description={t('events.deleteDescription')}
          submit={t('events.delete')}
          pending={remove.isPending}
          error={remove.error}
          errorFallback={remove.error instanceof EventRefusedError && remove.error.code === 'revisionConflict' ? t('events.changedElsewhere') : t('events.saveFailed')}
          onConfirm={() => remove.mutate(undefined, { onSuccess: () => finish(t('events.deleted')) })}
        />
      ) : null}
    </>
  )
}
