import { MicOff } from 'lucide-react'
import { useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { Avatar } from '@kutup/ui/components/avatar'
import { cn } from '@kutup/ui/lib/cn'

// The stage of a call through an SFU (a group call, a call link): a tile per
// participant, and a shared screen taking the stage with the participants in
// a strip beside it.

export interface StageParticipant {
  identity: string
  local: boolean
  name: string
  avatarName: string
  avatar?: string
  avatarContentType?: string
  audio: MediaStreamTrack | null
  video: MediaStreamTrack | null
  screen: MediaStreamTrack | null
  muted: boolean
  speaking: boolean
}

export function CallStage({ participants }: { participants: StageParticipant[] }) {
  const { t } = useTranslation()
  const sharer = participants.find((participant) => participant.screen)
  // On a phone two people stack; more share two columns.
  const columns =
    participants.length <= 1
      ? 'grid-cols-1'
      : participants.length === 2
        ? 'grid-cols-1 sm:grid-cols-2'
        : participants.length <= 4
          ? 'grid-cols-2'
          : 'grid-cols-2 md:grid-cols-3'
  const tiles = participants.map((participant) => (
    <Tile key={participant.identity} participant={participant} compact={sharer !== undefined} />
  ))
  if (!sharer) {
    return (
      <div className={cn('grid min-h-0 flex-1 auto-rows-fr gap-2 p-2', columns)}>
        {tiles}
      </div>
    )
  }
  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2 p-2 md:flex-row">
      <ScreenTile
        track={sharer.screen!}
        label={sharer.local ? t('chat.calls.youAreSharing') : t('chat.calls.screenOf', { name: sharer.name })}
      />
      <div className="flex shrink-0 gap-2 overflow-auto md:w-48 md:flex-col" data-testid="chat-group-call-strip">
        {tiles}
      </div>
    </div>
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

function Tile({ participant, compact }: { participant: StageParticipant; compact: boolean }) {
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
        // In the strip beside a shared screen.
        compact && 'aspect-video w-40 shrink-0 md:w-auto',
        participant.speaking && 'ring-2 ring-status-ok',
      )}
      data-testid="chat-group-call-tile"
      data-name={participant.name}
      data-video={participant.video ? 'on' : 'off'}
    >
      {participant.audio ? <audio ref={audio} autoPlay /> : null}
      {participant.video ? (
        <video ref={video} autoPlay playsInline muted className={cn('size-full object-cover', participant.local && '[transform:scaleX(-1)]')} />
      ) : (
        <Avatar name={participant.avatarName} image={participant.avatar} contentType={participant.avatarContentType} size={compact ? 48 : 80} />
      )}
      <span className="absolute bottom-2 left-2 flex max-w-[calc(100%-1rem)] items-center gap-1 rounded bg-stage/70 px-2 py-0.5 text-xs">
        {participant.muted ? <MicOff className="size-3 shrink-0" aria-hidden /> : null}
        <span className="truncate">{participant.name}</span>
      </span>
    </div>
  )
}
