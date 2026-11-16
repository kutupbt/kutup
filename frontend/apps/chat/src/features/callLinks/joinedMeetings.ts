import { isAxiosError } from 'axios'
import { loadChatWasm } from '@kutup/chat-core/wasm'
import { accountHead } from '@kutup/session/accountHead'
import type { Session } from '@kutup/session/store'
import { callLinkRoomId } from './callLinks'
import type { JoinedMeeting } from './meetingHistory'

// An account's joined meetings (docs/chat-calls.md, "History"): the same
// list on all of its devices. Each stay is sealed in the browser as an
// account record (purpose JoinedMeeting) bound to the account and its
// random id, and kept in the account-records store's `joinedMeetings` scope
// (docs/plans/account-records.md) under the account head. A stay is only
// ever added or removed; the scope's count is a site setting, and adding
// past it removes the oldest in the same batch.

const SCOPE = 'joinedMeetings'

type Account = Pick<Session, 'userId' | 'masterKeys' | 'roots' | 'envelopeBinding'>

/** The count the server allows when a batch would pass it (`scopeFull`), or null for any other error. */
function scopeFull(error: unknown): number | null {
  if (!isAxiosError(error) || error.response?.status !== 400) return null
  const data = error.response.data as { code?: string; scope?: string; max?: number } | undefined
  return data?.code === 'scopeFull' && data.scope === SCOPE && typeof data.max === 'number' ? data.max : null
}

/** The account's joined meetings, as its master keys open them (the head verified). */
export async function listJoinedMeetings(session: Account): Promise<JoinedMeeting[]> {
  const copy = await (await accountHead(session)).records(SCOPE)
  const wasm = await loadChatWasm()
  const entries: JoinedMeeting[] = []
  for (const [id, stored] of copy.records) {
    try {
      const opened = wasm.callLinkOpenJoined(session.masterKeys, session.envelopeBinding, id, stored.envelope)
      entries.push({ id, ...opened, roomId: callLinkRoomId(wasm, opened.fragment), account: session.userId })
    } catch {
      // A record this account's key does not open is not shown.
    }
  }
  return entries
}

/**
 * Puts stays in the account's list in one batch; ones already there change
 * nothing. When the list is full, the oldest are removed in the same batch
 * (a record that doesn't open counts as oldest).
 */
export async function addJoinedMeetings(session: Account, stays: readonly JoinedMeeting[]): Promise<void> {
  let max: number | null = null
  for (;;) {
    try {
      await (await accountHead(session)).recordsWrite(SCOPE, async (copy) => {
        const wasm = await loadChatWasm()
        let fresh = stays.filter((stay) => !copy.records.has(stay.id)).sort((a, b) => b.joinedAtMs - a.joinedAtMs)
        if (max !== null) fresh = fresh.slice(0, max)
        if (fresh.length === 0) return null
        const puts = fresh.map((stay) => ({
          id: stay.id,
          revision: 1,
          envelope: wasm.callLinkSealJoined(session.masterKeys, session.envelopeBinding, stay.id, {
            fragment: stay.fragment,
            title: stay.title,
            joinedAtMs: stay.joinedAtMs,
            seconds: stay.seconds,
          }),
        }))
        let deletes: string[] = []
        const over = max === null ? 0 : copy.records.size + puts.length - max
        if (over > 0) {
          const kept = [...copy.records].map(([id, stored]) => {
            try {
              return { id, at: wasm.callLinkOpenJoined(session.masterKeys, session.envelopeBinding, id, stored.envelope).joinedAtMs }
            } catch {
              return { id, at: -1 }
            }
          })
          deletes = kept
            .sort((a, b) => a.at - b.at || (a.id < b.id ? -1 : 1))
            .slice(0, over)
            .map((entry) => entry.id)
        }
        return { puts, deletes, done: undefined }
      })
      return
    } catch (error) {
      const allowed = scopeFull(error)
      if (allowed === null || max !== null) throw error
      // Read again and make room.
      max = allowed
    }
  }
}

export async function removeJoinedMeeting(session: Account, id: string): Promise<void> {
  await (await accountHead(session)).recordsWrite(SCOPE, (copy) =>
    Promise.resolve(copy.records.has(id) ? { puts: [], deletes: [id], done: undefined } : null),
  )
}

/** Clears the list, a batch at a time. */
export async function clearJoinedMeetings(session: Account): Promise<void> {
  const head = await accountHead(session)
  for (;;) {
    const left = await head.recordsWrite(SCOPE, (copy) => {
      const ids = [...copy.records.keys()].slice(0, CLEAR_BATCH)
      return Promise.resolve(ids.length ? { puts: [], deletes: ids, done: copy.records.size - ids.length } : null)
    })
    if (!left) return
  }
}

/** Deletions per batch while clearing: within the server's default batch size (256). */
const CLEAR_BATCH = 100
