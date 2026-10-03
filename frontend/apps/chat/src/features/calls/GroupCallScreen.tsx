import { Mic, MicOff, MonitorOff, MonitorUp, PhoneOff, Video, VideoOff } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { cn } from '@kutup/ui/lib/cn'
import { useChat } from '../../app/chatStore'
import { Avatar } from '@kutup/ui/components/avatar'
import { groupTitle, personName } from '../../lib/names'
import { canShareScreen, reportShareFailure } from './callController'
import { CallFrame, PanelButtons, RoundButton, type CallPanel, type CallPerson } from './CallFrame'
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
  // A shared screen takes the stage; the people move to a strip beside it.
  const sharer = call.participants.find((participant) => participant.screen)
  const columns = call.participants.length <= 1 ? 1 : call.participants.length <= 4 ? 2 : 3
  const people: CallPerson[] = call.participants.map((participant) => {
    const profile = participant.local ? (snapshot.profile ?? undefined) : participant.address ? profiles.get(participant.address) : undefined
    return {
      key: participant.identity,
      name: nameOf(participant),
      avatarName: participant.local ? (snapshot.profile?.displayName || self?.address || nameOf(participant)) : nameOf(participant),
      avatar: profile?.avatar,
      avatarContentType: profile?.avatarContentType,
      muted: participant.muted,
      cameraOn: participant.video !== null,
      sharing: participant.screen !== null,
    }
  })
  const tiles = call.participants.map((participant) => (
    <Tile
      key={participant.identity}
      participant={participant}
      name={nameOf(participant)}
      avatarName={participant.local ? (snapshot.profile?.displayName || self?.address || nameOf(participant)) : nameOf(participant)}
      profile={participant.local ? (snapshot.profile ?? undefined) : participant.address ? profiles.get(participant.address) : undefined}
      compact={sharer !== undefined}
    />
  ))

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
      {sharer ? (
        <div className="flex min-h-0 flex-1 flex-col gap-2 p-2 md:flex-row">
          <ScreenTile track={sharer.screen!} label={sharer.local ? t('chat.calls.youAreSharing') : t('chat.calls.screenOf', { name: nameOf(sharer) })} />
          <div className="flex shrink-0 gap-2 overflow-auto md:w-48 md:flex-col" data-testid="chat-group-call-strip">
            {tiles}
          </div>
        </div>
      ) : (
        <div className="grid min-h-0 flex-1 gap-2 p-2" style={{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }}>
          {tiles}
        </div>
      )}
    </CallFrame>
  )
}

function ScreenTile({ track, label }: { track: MediaStreamTrack; label: string }) {
  const video = useRef<HTMLVideoElement>(null)
  useEffect(() => {
    if (video.current) video.current.srcObject = new MediaStream([track])
  }, [track])
  return (
    <div className="relative flex min-h-0 min-w-0 flex-1 items-center justify-center overflow-hidden rounded-xl bg-black" data-testid="chat-group-call-screen-tile">
      <video ref={video} autoPlay playsInline muted className="size-full object-contain" />
      <span className="absolute left-2 top-2 rounded bg-stage/70 px-2 py-0.5 text-xs">{label}</span>
    </div>
  )
}

function Tile({
  participant,
  name,
  avatarName,
  profile,
  compact,
}: {
  participant: GroupCallParticipant
  name: string
  avatarName: string
  profile?: { avatar?: string; avatarContentType?: string }
  /** In the strip beside a shared screen. */
  compact: boolean
}) {
  const video = useRef<HTMLVideoElement>(null)
  const audio = useRef<HTMLAudioElement>(null)
  useEffect(() => {
    if (video.current) video.current.srcObject = participant.video ? new MediaStream([participant.video]) : null
  }, [participant.video])
  useEffect(() => {
    if (audio.current) audio.current.srcObject = participant.audio ? new MediaStream([participant.audio]) : null
  }, [participant.audio])
  return (
    <div
      className={cn(
        'relative flex min-h-0 items-center justify-center overflow-hidden rounded-xl bg-stage-accent',
        compact && 'aspect-video w-40 shrink-0 md:w-auto',
        participant.speaking && 'ring-2 ring-status-ok',
      )}
      data-testid="chat-group-call-tile"
      data-name={name}
      data-video={participant.video ? 'on' : 'off'}
    >
      {participant.audio ? <audio ref={audio} autoPlay /> : null}
      {participant.video ? (
        <video ref={video} autoPlay playsInline muted className={cn('size-full object-cover', participant.local && '[transform:scaleX(-1)]')} />
      ) : (
        <Avatar name={avatarName} image={profile?.avatar} contentType={profile?.avatarContentType} size={compact ? 48 : 80} />
      )}
      <span className="absolute bottom-2 left-2 flex items-center gap-1 rounded bg-stage/70 px-2 py-0.5 text-xs">
        {participant.muted ? <MicOff className="size-3" aria-hidden /> : null}
        {name}
      </span>
    </div>
  )
}
