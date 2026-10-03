import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useSyncExternalStore } from 'react'
import { useRequiredSession } from '@kutup/session/store'
import { createCallLink, deleteCallLink, listCallLinks, updateCallLinkInfo, type MeetingInfo, type OwnedCallLink } from './callLinks'
import { joinedMeetings, subscribeJoinedMeetings, type JoinedMeeting } from './meetingHistory'

const QUERY = ['chat-meetings'] as const

/** The account's meetings and the ways to make, change and delete one. */
export function useMeetings(enabled = true) {
  const session = useRequiredSession()
  const queryClient = useQueryClient()
  const update = (change: (previous: OwnedCallLink[]) => OwnedCallLink[]) =>
    queryClient.setQueryData<OwnedCallLink[]>(QUERY, (previous) => change(previous ?? []))
  const list = useQuery({ queryKey: QUERY, queryFn: () => listCallLinks(session.masterKey), enabled })
  const create = useMutation({
    mutationFn: (info: MeetingInfo) => createCallLink(session.masterKey, info),
    onSuccess: (meeting) => update((previous) => [meeting, ...previous]),
  })
  const change = useMutation({
    mutationFn: ({ meeting, info }: { meeting: OwnedCallLink; info: MeetingInfo }) => updateCallLinkInfo(meeting, info),
    onSuccess: (meeting) => update((previous) => previous.map((other) => (other.roomId === meeting.roomId ? meeting : other))),
  })
  const remove = useMutation({
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

/** The meetings this browser joined, newest first. */
export function useJoinedMeetings(): JoinedMeeting[] {
  return useSyncExternalStore(subscribeJoinedMeetings, snapshot)
}
