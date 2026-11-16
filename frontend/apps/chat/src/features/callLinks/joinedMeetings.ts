import { loadChatWasm } from '@kutup/chat-core/wasm'
import type { MasterKeys } from '@kutup/crypto/masterKeys'
import api from '@kutup/session/client'
import { callLinkRoomId } from './callLinks'
import type { JoinedMeeting } from './meetingHistory'

// An account's joined meetings (docs/chat-calls.md, "History"): the same
// list on all of its devices. Each stay is sealed in the browser as an
// account record (docs/plans/w1-account-record.md) bound to the account
// and its row; the server checks the record's header and reads none of it.

/** The account's joined meetings, as its master keys open them. */
export async function listJoinedMeetings(masterKeys: MasterKeys, binding: string, account: string): Promise<JoinedMeeting[]> {
  const { data } = await api.get<{ entries: { id: string; entry: string }[] }>('/chat/joined-meetings')
  const wasm = await loadChatWasm()
  const entries: JoinedMeeting[] = []
  for (const { id, entry } of data.entries) {
    try {
      const opened = wasm.callLinkOpenJoined(masterKeys, binding, id, entry)
      entries.push({ id, ...opened, roomId: callLinkRoomId(wasm, opened.fragment), account })
    } catch {
      // A record this account's key does not open is not shown.
    }
  }
  return entries
}

/** Put a stay in the account's list. The same stay again changes nothing. */
export async function addJoinedMeeting(masterKeys: MasterKeys, binding: string, stay: JoinedMeeting): Promise<void> {
  const wasm = await loadChatWasm()
  const entry = wasm.callLinkSealJoined(masterKeys, binding, stay.id, {
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
