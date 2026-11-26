import { instantOf } from '@kutup/calendar-core/api'
import { meetingInfoOf } from '@kutup/calendar-core/meetings'
import { formOf, type Draft } from '../eventDraft'

/** The event's meeting info as the draft says now: its title and time. */
export async function draftMeetingInfo(draft: Draft, weekStart: number, fallbackTitle: string) {
  const form = await formOf({ ...draft, frequency: null }, weekStart, null)
  const startUtc = await instantOf(form.start)
  const endUtc = form.end ? await instantOf(form.end) : startUtc
  return meetingInfoOf({ title: draft.title, startUtc, endUtc, fullDay: draft.allDay }, fallbackTitle)
}
