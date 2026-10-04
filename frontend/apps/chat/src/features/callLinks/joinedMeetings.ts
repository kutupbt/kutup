import { loadChatWasm } from '@kutup/chat-core/wasm'
import { toBase64 } from '@kutup/crypto'
import api from '@kutup/session/client'
import { callLinkRoomId } from './callLinks'
import type { JoinedMeeting } from './meetingHistory'

// An account's joined meetings (docs/chat-calls.md, "History"): the same
// list on all of its devices. Each stay is sealed in the browser under a
// key from the account master key; the server stores the records and reads
// none of them.

/** The account's joined meetings, as its key opens them. */
export async function listJoinedMeetings(masterKey: Uint8Array, account: string): Promise<JoinedMeeting[]> {
  const { data } = await api.get<{ entries: { id: string; entry: string }[] }>('/chat/joined-meetings')
  const wasm = await loadChatWasm()
  const key = toBase64(masterKey)
  const entries: JoinedMeeting[] = []
  for (const { id, entry } of data.entries) {
    try {
      const opened = wasm.callLinkOpenJoined(key, entry)
      entries.push({ id, ...opened, roomId: callLinkRoomId(wasm, opened.fragment), account })
    } catch {
      // A record this account's key does not open is not shown.
    }
  }
  return entries
}

/** Put a stay in the account's list. The same stay again changes nothing. */
export async function addJoinedMeeting(masterKey: Uint8Array, stay: JoinedMeeting): Promise<void> {
  const wasm = await loadChatWasm()
  const entry = wasm.callLinkSealJoined(toBase64(masterKey), {
    fragment: stay.fragment,
    title: stay.title,
    joinedAtMs: stay.joinedAtMs,
    seconds: stay.seconds,
  })
  await api.post('/chat/joined-meetings', { id: stay.id, entry })
}

export async function removeJoinedMeeting(id: string): Promise<void> {
  await api.delete(`/chat/joined-meetings/${id}`)
}

export async function clearJoinedMeetings(): Promise<void> {
  await api.delete('/chat/joined-meetings')
}
