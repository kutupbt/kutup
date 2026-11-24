import { deleteEvent, EventRefusedError, loadEvent, saveEvent, type Calendar } from '@kutup/calendar-core/api'
import type { MailAccount } from '@kutup/mail-core/api'
import type { Session } from '@kutup/session/store'
import type { Step } from './actions'

/**
 * A planned series change and the steps of it that have landed: a retry
 * (Save again after a failure) sends only the others (docs/plans/
 * calendar.md, E2 §2 Q-1). Each step is idempotent: a create carries its
 * drawn id, a delete of an event gone is done, an update that landed but
 * whose answer was lost reads as a revision conflict whose stored event is
 * the planned one.
 */
export interface Plan {
  steps: Step[]
  done: Set<number>
}

export function planOf(steps: Step[]): Plan {
  return { steps, done: new Set() }
}

function sameRule(a: { rrule: string | null; exdates?: unknown[]; summary: string | null }, b: typeof a): boolean {
  return a.rrule === b.rrule && JSON.stringify(a.exdates ?? []) === JSON.stringify(b.exdates ?? []) && a.summary === b.summary
}

/** Sends the steps not yet landed, in order, one sync change each; stops at the first refused. */
export async function runPlan(plan: Plan, session: Session, account: MailAccount, calendar: Calendar): Promise<void> {
  for (const [index, step] of plan.steps.entries()) {
    if (plan.done.has(index)) continue
    try {
      if (step.kind === 'delete') await deleteEvent(session, account, calendar, step.event)
      else if (step.kind === 'update') await saveEvent(session, account, calendar, step.fields, step.event, step.reminders)
      else await saveEvent(session, account, calendar, step.fields, undefined, step.reminders, step.id)
    } catch (error) {
      if (!(error instanceof EventRefusedError)) throw error
      // A delete of an event already gone has happened.
      if (step.kind === 'delete' && error.status === 404) {
        plan.done.add(index)
        continue
      }
      // An update another attempt landed: the stored event is the planned one.
      if (step.kind === 'update' && error.code === 'revisionConflict') {
        const stored = await loadEvent(account, calendar, step.event.id).catch(() => null)
        if (stored && sameRule(stored.fields, step.fields)) {
          plan.done.add(index)
          continue
        }
      }
      throw error
    }
    plan.done.add(index)
  }
}
