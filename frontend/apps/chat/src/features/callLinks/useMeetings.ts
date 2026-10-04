import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, useRef, useSyncExternalStore } from 'react'
import { useRequiredSession } from '@kutup/session/store'
import { createCallLink, deleteCallLink, listCallLinks, setWaitingRoom, updateCallLinkInfo, type MeetingInfo, type OwnedCallLink } from './callLinks'
import { addJoinedMeeting, clearJoinedMeetings, listJoinedMeetings, removeJoinedMeeting } from './joinedMeetings'
import { forgetJoinedMeetings, joinedMeetings, setHistoryAccount, subscribeJoinedMeetings, type JoinedMeeting } from './meetingHistory'

const QUERY = ['chat-meetings'] as const

/** What a person sets on a meeting. */
export interface MeetingDraft {
  info: MeetingInfo
  /** People who open the link wait until the owner lets them in. */
  waitingRoom: boolean
}

/** The account's meetings and the ways to make, change and delete one. */
export function useMeetings(enabled = true) {
  const session = useRequiredSession()
  const queryClient = useQueryClient()
  const update = (change: (previous: OwnedCallLink[]) => OwnedCallLink[]) =>
    queryClient.setQueryData<OwnedCallLink[]>(QUERY, (previous) => change(previous ?? []))
  // A list asked for before a change would bring the old state back when it
  // arrives: it is dropped, and the list is asked for again afterwards.
  const settle = {
    onMutate: () => queryClient.cancelQueries({ queryKey: QUERY }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: QUERY }),
  }
  const list = useQuery({ queryKey: QUERY, queryFn: () => listCallLinks(session.masterKey), enabled })
  const create = useMutation({
    ...settle,
    mutationFn: ({ info, waitingRoom }: MeetingDraft) => createCallLink(session.masterKey, info, waitingRoom),
    onSuccess: (meeting) => update((previous) => [meeting, ...previous]),
  })
  const change = useMutation({
    ...settle,
    mutationFn: async ({ meeting, draft }: { meeting: OwnedCallLink; draft: MeetingDraft }) => {
      let next = await updateCallLinkInfo(meeting, draft.info)
      if (draft.waitingRoom !== meeting.waitingRoom) next = await setWaitingRoom(session.masterKey, next, draft.waitingRoom)
      return next
    },
    onSuccess: (meeting) => update((previous) => previous.map((other) => (other.roomId === meeting.roomId ? meeting : other))),
  })
  const remove = useMutation({
    ...settle,
    mutationFn: (meeting: OwnedCallLink) => deleteCallLink(meeting.roomId),
    onSuccess: (_result, meeting) => update((previous) => previous.filter((other) => other.roomId !== meeting.roomId)),
  })
  return { list, create, change, remove }
}

let cached: { raw: string; entries: JoinedMeeting[] } = { raw: '', entries: [] }

function snapshot(): JoinedMeeting[] {
  const entries = joinedMeetings()
  const raw = JSON.stringify(entries)
  // The same array while nothing changed, as useSyncExternalStore needs.
  if (raw !== cached.raw) cached = { raw, entries }
  return cached.entries
}

const JOINED_QUERY = ['chat-joined-meetings'] as const

/** The stays in this browser's storage that belong in `userId`'s list. */
function theirs(local: JoinedMeeting[], userId: string): JoinedMeeting[] {
  // Joined while this account was signed in here, or while nobody was.
  return local.filter((entry) => entry.account === undefined || entry.account === userId)
}

/**
 * Moves the stays the meeting page left in this browser into the account's
 * list, whatever is on screen: so a meeting joined here shows on the
 * account's other devices too. A stay that cannot be moved now stays here
 * and is tried again.
 */
export function useJoinedMeetingsSync(): void {
  const session = useRequiredSession()
  const queryClient = useQueryClient()
  const local = useSyncExternalStore(subscribeJoinedMeetings, snapshot)
  const moving = useRef(false)
  const { userId, masterKey } = session

  useEffect(() => {
    setHistoryAccount(userId)
    return () => setHistoryAccount(null)
  }, [userId])

  useEffect(() => {
    const pending = theirs(local, userId)
    if (pending.length === 0 || moving.current) return
    moving.current = true
    void (async () => {
      const moved = new Set<string>()
      try {
        // Oldest first, so the server's order is the order they happened in.
        for (const stay of [...pending].reverse()) {
          await addJoinedMeeting(masterKey, stay)
          moved.add(stay.id)
        }
      } catch (error) {
        console.warn('chat: a joined meeting did not reach the account yet', error)
      } finally {
        moving.current = false
        if (moved.size > 0) {
          await queryClient.invalidateQueries({ queryKey: JOINED_QUERY })
          forgetJoinedMeetings(moved)
        }
      }
    })()
  }, [local, userId, masterKey, queryClient])
}

/**
 * The meetings this account joined, newest first, on any of its devices,
 * with the ones joined in this browser that have not reached the account
 * yet; and the ways to take one off the list or clear it.
 */
export function useJoinedMeetings() {
  const session = useRequiredSession()
  const queryClient = useQueryClient()
  const local = useSyncExternalStore(subscribeJoinedMeetings, snapshot)
  const list = useQuery({ queryKey: JOINED_QUERY, queryFn: () => listJoinedMeetings(session.masterKey) })
  const entries = useMemo(() => {
    const byId = new Map<string, JoinedMeeting>()
    for (const entry of [...theirs(local, session.userId), ...(list.data ?? [])]) byId.set(entry.id, entry)
    return [...byId.values()].sort((a, b) => b.joinedAtMs - a.joinedAtMs)
  }, [local, list.data, session.userId])
  const settle = {
    onMutate: () => queryClient.cancelQueries({ queryKey: JOINED_QUERY }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: JOINED_QUERY }),
  }
  const forget = useMutation({
    ...settle,
    mutationFn: async (entry: JoinedMeeting) => {
      forgetJoinedMeetings(new Set([entry.id]))
      await removeJoinedMeeting(entry.id)
    },
    onSuccess: (_result, entry) =>
      queryClient.setQueryData<JoinedMeeting[]>(JOINED_QUERY, (previous) => (previous ?? []).filter((other) => other.id !== entry.id)),
  })
  const clear = useMutation({
    ...settle,
    mutationFn: async () => {
      forgetJoinedMeetings(new Set(theirs(joinedMeetings(), session.userId).map((entry) => entry.id)))
      await clearJoinedMeetings()
    },
    onSuccess: () => queryClient.setQueryData<JoinedMeeting[]>(JOINED_QUERY, []),
  })
  return { entries, forget, clear }
}
