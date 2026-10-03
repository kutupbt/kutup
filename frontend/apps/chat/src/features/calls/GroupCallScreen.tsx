import { Mic, MicOff, MonitorOff, MonitorUp, PhoneOff, Video, VideoOff } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useChat } from '../../app/chatStore'
import { groupTitle, personName } from '../../lib/names'
import { canShareScreen, reportShareFailure } from './callController'
import { CallFrame, PanelButtons, RoundButton, type CallPanel, type CallPerson } from './CallFrame'
import { CallStage, type StageParticipant } from './CallStage'
import { groupCallController, useGroupCall } from './callStore'
import type { GroupCallParticipant, GroupCallState } from './groupCallController'

/** A group call in progress, over everything else: a tile per participant. */
export function GroupCallScreen() {
  const call = useGroupCall()
  return call ? <Screen call={call} /> : null
}

function Screen({ call }: { call: GroupCallState }) {
  const { t } = useTranslation()
  const { snapshot, self } = useChat()
  const controller = groupCallController()
  const profiles = new Map(snapshot.profiles.map((p) => [p.peer, p]))
  const group = snapshot.groups.find((g) => g.request.genesis.conversationId === call.groupId)
  const title = groupTitle(call.groupId, t, group?.currentGroupInfo)
  const nameOf = (participant: GroupCallParticipant) =>
    participant.local
      ? t('chat.you')
      : participant.address
        ? personName(participant.address, profiles, self?.address ?? '', t)
        : t('chat.calls.unknownParticipant')
  const status = call.phase === 'connecting'
    ? t('chat.calls.connecting')
    : call.phase === 'ended'
      ? call.failed ? t('chat.calls.ended.failed') : t('chat.calls.ended.hungUp')
      : t('chat.calls.inCall', { count: call.participants.length })
  const [panel, setPanel] = useState<CallPanel | null>(null)
  const participants: StageParticipant[] = call.participants.map((participant) => {
    const profile = participant.local ? (snapshot.profile ?? undefined) : participant.address ? profiles.get(participant.address) : undefined
    const name = nameOf(participant)
    return {
      ...participant,
      name,
      avatarName: participant.local ? (snapshot.profile?.displayName || self?.address || name) : name,
      avatar: profile?.avatar,
      avatarContentType: profile?.avatarContentType,
    }
  })
  const people: CallPerson[] = participants.map((participant) => ({
    key: participant.identity,
    name: participant.name,
    avatarName: participant.avatarName,
    avatar: participant.avatar,
    avatarContentType: participant.avatarContentType,
    muted: participant.muted,
    cameraOn: participant.video !== null,
    sharing: participant.screen !== null,
  }))

  return (
    <CallFrame
      label={t('chat.calls.groupScreen', { name: title })}
      title={title}
      status={status}
      phase={call.phase}
      testId="chat-group-call-screen"
      statusTestId="chat-group-call-status"
      people={people}
      conversation={{ kind: 'group', groupId: call.groupId }}
      panel={call.phase === 'ended' ? null : panel}
      onPanel={setPanel}
      controls={
        call.phase !== 'ended' ? (
          <>
            <RoundButton label={call.muted ? t('chat.calls.unmute') : t('chat.calls.mute')} pressed={call.muted} onClick={() => controller?.toggleMute()} testId="chat-group-call-mute">
              {call.muted ? <MicOff /> : <Mic />}
            </RoundButton>
            <RoundButton label={call.cameraOn ? t('chat.calls.cameraOff') : t('chat.calls.cameraOn')} pressed={!call.cameraOn} onClick={() => void controller?.toggleCamera()} testId="chat-group-call-camera">
              {call.cameraOn ? <Video /> : <VideoOff />}
            </RoundButton>
            {canShareScreen() && call.phase === 'active' ? (
              <RoundButton
                label={call.screenOn ? t('chat.calls.stopSharing') : t('chat.calls.shareScreen')}
                pressed={call.screenOn}
                onClick={() => void controller?.toggleScreen().catch((error: unknown) => reportShareFailure(error, t('chat.calls.shareFailed')))}
                testId="chat-group-call-screen-share"
              >
                {call.screenOn ? <MonitorOff /> : <MonitorUp />}
              </RoundButton>
            ) : null}
            <PanelButtons panel={panel} onPanel={setPanel} chat />
            <RoundButton label={t('chat.calls.leave')} tone="danger" onClick={() => void controller?.leave()} testId="chat-group-call-leave">
              <PhoneOff />
            </RoundButton>
          </>
        ) : null
      }
    >
      <CallStage participants={participants} />
    </CallFrame>
  )
}
