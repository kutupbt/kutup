import { useEffect, useRef } from 'react'
import { isKutupMeeting } from '@kutup/calendar-core/meetings'
import { utcToLocal } from '@kutup/crypto/calendar'
import { openEditor, type EditorTarget } from '../editorState'

// Chat's "Add to Kutup Calendar" (docs/plans/calendar.md, E5c): Chat opens
// Calendar with the meeting in the address's fragment, which no server
// sees (the link's secret is in it): `#meeting=<link>&title=…&start=<ms>&minutes=<n>`.
// The editor opens filled in, for the person to check and save; nothing is
// saved by the link. Only a meeting link of this server's Chat is taken.

const MAX_TITLE_CHARS = 255

/** The new event a fragment asks for, in `zone`; null when it is not a meeting of this server's Chat. */
export async function meetingTarget(fragment: string, zone: string, today: string): Promise<EditorTarget | null> {
  const params = new URLSearchParams(fragment.replace(/^#/, ''))
  const url = params.get('meeting')
  if (!url || !isKutupMeeting(url)) return null
  const title = (params.get('title') ?? '').replace(/\p{Cc}/gu, ' ').trim().slice(0, MAX_TITLE_CHARS)
  const start = Number(params.get('start'))
  const minutes = Number(params.get('minutes'))
  if (!Number.isSafeInteger(start) || start <= 0) return { kind: 'new', date: today, title, conference: url }
  const local = await utcToLocal(new Date(start).toISOString().replace(/\.\d+Z$/, 'Z'), zone)
  const at = Number(local.slice(11, 13)) * 60 + Number(local.slice(14, 16))
  const length = Number.isSafeInteger(minutes) && minutes >= 1 && minutes <= 24 * 60 ? minutes : 30
  const end = at + length
  const date = local.slice(0, 10)
  return {
    kind: 'new',
    date,
    minutes: at,
    endMinutes: end % (24 * 60),
    endDate: end >= 24 * 60 ? nextDay(date) : date,
    title,
    conference: url,
  }
}

function nextDay(date: string): string {
  const day = new Date(`${date}T00:00:00Z`)
  day.setUTCDate(day.getUTCDate() + 1)
  return day.toISOString().slice(0, 10)
}

/**
 * Opens the editor for a meeting Chat sent here, once, and clears the
 * fragment (the link's secret) from the address and its history entry.
 */
export function useMeetingLink(zone: string, today: string | undefined, ready: boolean): void {
  const handled = useRef(false)
  useEffect(() => {
    if (handled.current || !ready || !today) return
    const fragment = window.location.hash
    if (!fragment.includes('meeting=')) return
    handled.current = true
    window.history.replaceState(window.history.state, '', window.location.pathname + window.location.search)
    void meetingTarget(fragment, zone, today).then((target) => {
      if (target) openEditor(target)
    })
  }, [ready, zone, today])
}
