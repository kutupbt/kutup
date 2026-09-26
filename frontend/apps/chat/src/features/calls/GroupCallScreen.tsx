import { Mic, MicOff, PhoneOff, Video, VideoOff } from 'lucide-react'
import { useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { cn } from '@kutup/ui/lib/cn'
import { useChat } from '../../app/chatStore'
import { Avatar } from '../../components/Avatar'
import { groupTitle, personName } from '../../lib/names'
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
  const columns = call.participants.length <= 1 ? 1 : call.participants.length <= 4 ? 2 : 3

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-stage text-stage-foreground" role="dialog" aria-modal aria-label={t('chat.calls.groupScreen', { name: title })} data-testid="chat-group-call-screen" data-phase={call.phase}>
      <header className="flex shrink-0 items-center gap-2 px-4 py-3">
        <h2 className="font-semibold">{title}</h2>
        <span className="text-sm text-stage-muted" data-testid="chat-group-call-status">{status}</span>
      </header>
      <div className="grid min-h-0 flex-1 gap-2 p-2" style={{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }}>
        {call.participants.map((participant) => (
          <Tile
            key={participant.identity}
            participant={participant}
            name={nameOf(participant)}
            avatarName={participant.local ? (snapshot.profile?.displayName || self?.address || nameOf(participant)) : nameOf(participant)}
            profile={participant.local ? (snapshot.profile ?? undefined) : participant.address ? profiles.get(participant.address) : undefined}
          />
        ))}
      </div>
      {call.phase !== 'ended' ? (
        <div className="flex shrink-0 items-center justify-center gap-4 pb-8 pt-3">
          <RoundButton label={call.muted ? t('chat.calls.unmute') : t('chat.calls.mute')} pressed={call.muted} onClick={() => controller?.toggleMute()} testId="chat-group-call-mute">
            {call.muted ? <MicOff /> : <Mic />}
          </RoundButton>
          <RoundButton label={call.cameraOn ? t('chat.calls.cameraOff') : t('chat.calls.cameraOn')} pressed={!call.cameraOn} onClick={() => void controller?.toggleCamera()} testId="chat-group-call-camera">
            {call.cameraOn ? <Video /> : <VideoOff />}
          </RoundButton>
          <RoundButton label={t('chat.calls.leave')} danger onClick={() => void controller?.leave()} testId="chat-group-call-leave">
            <PhoneOff />
          </RoundButton>
        </div>
      ) : null}
    </div>
  )
}

function Tile({
  participant,
  name,
  avatarName,
  profile,
}: {
  participant: GroupCallParticipant
  name: string
  avatarName: string
  profile?: { avatar?: string; avatarContentType?: string }
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
        <Avatar name={avatarName} image={profile?.avatar} contentType={profile?.avatarContentType} size={80} />
      )}
      <span className="absolute bottom-2 left-2 flex items-center gap-1 rounded bg-stage/70 px-2 py-0.5 text-xs">
        {participant.muted ? <MicOff className="size-3" aria-hidden /> : null}
        {name}
      </span>
    </div>
  )
}

function RoundButton({
  label,
  onClick,
  children,
  danger,
  pressed,
  testId,
}: {
  label: string
  onClick: () => void
  children: React.ReactNode
  danger?: boolean
  pressed?: boolean
  testId: string
}) {
  return (
    <Button
      type="button"
      size="icon"
      onClick={onClick}
      aria-label={label}
      title={label}
      aria-pressed={pressed}
      className={cn(
        'size-14 rounded-full [&_svg]:size-6',
        danger
          ? 'bg-destructive text-destructive-foreground hover:bg-destructive/90'
          : pressed
            ? 'bg-stage-foreground text-stage hover:bg-stage-foreground/90'
            : 'bg-stage-accent text-stage-foreground hover:bg-stage-active',
      )}
      data-testid={testId}
    >
      {children}
    </Button>
  )
}
