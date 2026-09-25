import { Mic, MicOff, Phone, PhoneOff, Video, VideoOff } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { cn } from '@kutup/ui/lib/cn'
import { getChatState, useChat } from '../../app/chatStore'
import { Avatar } from '../../components/Avatar'
import { formatDuration } from '../../lib/callText'
import { personName } from '../../lib/names'
import { notificationsAllowed } from '../../lib/notificationPermission'
import { startRingtone } from '../../lib/ringtone'
import { useNow } from '../../lib/useNow'
import { getAlwaysRelayCalls, getNotifications } from '../../state/prefs'
import { CallController, type CallState } from './callController'
import { callController, setCallController, setGroupCallController, useCall } from './callStore'
import { GroupCallController } from './groupCallController'
import { GroupCallRinger } from './GroupCallRinger'
import { GroupCallScreen } from './GroupCallScreen'

/**
 * The chat's call controller and, while a call rings or runs, the call
 * screen over everything else.
 */
export function CallHost() {
  const { service, self } = useChat()
  const address = self?.address
  useEffect(() => {
    if (!service || !address) return
    const controller = new CallController(service, address, () => ({ alwaysRelay: getAlwaysRelayCalls() }))
    const group = new GroupCallController(service, address, () => getChatState().snapshot.groups)
    setCallController(controller)
    setGroupCallController(group)
    return () => {
      setCallController(null)
      setGroupCallController(null)
      controller.dispose()
      group.dispose()
    }
  }, [service, address])
  const call = useCall()
  return (
    <>
      {call ? <CallScreen call={call} /> : null}
      <GroupCallScreen />
      <GroupCallRinger />
    </>
  )
}

function CallScreen({ call }: { call: CallState }) {
  const { t } = useTranslation()
  const { snapshot, self } = useChat()
  const profiles = new Map(snapshot.profiles.map((p) => [p.peer, p]))
  const profile = profiles.get(call.peer)
  const name = personName(call.peer, profiles, self?.address ?? '', t)
  const remoteVideo = useRef<HTMLVideoElement>(null)
  const localVideo = useRef<HTMLVideoElement>(null)
  const remoteAudio = useRef<HTMLAudioElement>(null)
  const [busy, setBusy] = useState(false)
  const now = useNow(1000)
  const controller = callController()

  useEffect(() => {
    if (remoteVideo.current) remoteVideo.current.srcObject = call.remoteStream
    if (remoteAudio.current) remoteAudio.current.srcObject = call.remoteStream
  }, [call.remoteStream])
  useEffect(() => {
    if (localVideo.current) localVideo.current.srcObject = call.localStream
  }, [call.localStream])

  // A remote video track exists from the start; it carries frames only while
  // the other side's camera is on (the track unmutes).
  const [remoteHasVideo, setRemoteHasVideo] = useState(false)
  useEffect(() => {
    const tracks = call.remoteStream?.getVideoTracks() ?? []
    const update = () => setRemoteHasVideo(tracks.some((track) => !track.muted && track.readyState === 'live'))
    update()
    for (const track of tracks) {
      track.addEventListener('mute', update)
      track.addEventListener('unmute', update)
      track.addEventListener('ended', update)
    }
    return () => {
      for (const track of tracks) {
        track.removeEventListener('mute', update)
        track.removeEventListener('unmute', update)
        track.removeEventListener('ended', update)
      }
    }
  }, [call.remoteStream])

  // Ring, and notify when the tab is out of sight.
  useEffect(() => {
    if (call.phase !== 'incoming') return
    const stop = startRingtone()
    let notification: Notification | null = null
    if (document.visibilityState !== 'visible' && getNotifications() && notificationsAllowed()) {
      notification = new Notification(name, {
        body: call.media === 'video' ? t('chat.calls.incomingVideo') : t('chat.calls.incomingVoice'),
        tag: `kutup-call:${call.callId}`,
        icon: '/favicon.svg',
        requireInteraction: true,
      })
      notification.onclick = () => {
        window.focus()
        notification?.close()
      }
    }
    return () => {
      stop()
      notification?.close()
    }
  }, [call.phase, call.callId, call.media, name, t])

  async function act(work: () => Promise<void> | void) {
    if (busy) return
    setBusy(true)
    try {
      await work()
    } catch (error) {
      console.warn('chat: call action failed', error)
    } finally {
      setBusy(false)
    }
  }

  const status = statusText(call, now, t)

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-chrome text-chrome-foreground" role="dialog" aria-modal aria-label={t('chat.calls.screen', { name })} data-testid="chat-call-screen" data-phase={call.phase}>
      <audio ref={remoteAudio} autoPlay />
      <div className="relative flex min-h-0 flex-1 items-center justify-center">
        <video
          ref={remoteVideo}
          autoPlay
          playsInline
          muted
          className={cn('absolute inset-0 size-full object-contain', !(remoteHasVideo && call.phase === 'active') && 'invisible')}
          data-testid="chat-call-remote-video"
        />
        {!(remoteHasVideo && call.phase === 'active') ? (
          <div className="flex flex-col items-center gap-3 text-center">
            <Avatar name={name} image={profile?.avatar} contentType={profile?.avatarContentType} size={80} />
            <h2 className="text-2xl font-semibold">{name}</h2>
            <p className="text-sm text-chrome-muted" data-testid="chat-call-status">{status}</p>
          </div>
        ) : (
          <p className="absolute left-4 top-4 rounded bg-black/50 px-2 py-1 text-sm" data-testid="chat-call-status">{name} · {status}</p>
        )}
        {call.cameraOn && call.localStream ? (
          <video
            ref={localVideo}
            autoPlay
            playsInline
            muted
            className="absolute bottom-4 right-4 h-32 w-48 rounded-lg border border-white/20 bg-black object-cover [transform:scaleX(-1)]"
            data-testid="chat-call-local-video"
          />
        ) : null}
      </div>
      <div className="flex shrink-0 items-center justify-center gap-4 pb-10 pt-4">
        {call.phase === 'incoming' ? (
          <>
            <RoundButton label={t('chat.calls.decline')} tone="danger" onClick={() => void act(() => controller?.decline())} testId="chat-call-decline">
              <PhoneOff />
            </RoundButton>
            <RoundButton label={t('chat.calls.acceptVoice')} tone="accept" onClick={() => void act(() => controller?.accept(false))} testId="chat-call-accept">
              <Phone />
            </RoundButton>
            {call.media === 'video' ? (
              <RoundButton label={t('chat.calls.acceptVideo')} tone="accept" onClick={() => void act(() => controller?.accept(true))} testId="chat-call-accept-video">
                <Video />
              </RoundButton>
            ) : null}
          </>
        ) : call.phase === 'ended' ? null : (
          <>
            <RoundButton label={call.muted ? t('chat.calls.unmute') : t('chat.calls.mute')} onClick={() => controller?.toggleMute()} pressed={call.muted} testId="chat-call-mute">
              {call.muted ? <MicOff /> : <Mic />}
            </RoundButton>
            <RoundButton label={call.cameraOn ? t('chat.calls.cameraOff') : t('chat.calls.cameraOn')} onClick={() => void act(() => controller?.toggleCamera())} pressed={!call.cameraOn} testId="chat-call-camera">
              {call.cameraOn ? <Video /> : <VideoOff />}
            </RoundButton>
            <RoundButton label={t('chat.calls.hangUp')} tone="danger" onClick={() => void act(() => controller?.hangUp())} testId="chat-call-hangup">
              <PhoneOff />
            </RoundButton>
          </>
        )}
      </div>
    </div>
  )
}

function statusText(call: CallState, now: number, t: (key: string, options?: Record<string, unknown>) => string): string {
  switch (call.phase) {
    case 'incoming':
      return call.media === 'video' ? t('chat.calls.incomingVideo') : t('chat.calls.incomingVoice')
    case 'outgoing':
      return t('chat.calls.ringing')
    case 'connecting':
      return t('chat.calls.connecting')
    case 'active':
      return formatDuration(Math.max(0, Math.floor((now - (call.connectedAtMs ?? now)) / 1000)))
    case 'ended':
      return t(`chat.calls.ended.${call.endReason ?? 'hungUp'}`)
  }
}

function RoundButton({
  label,
  onClick,
  children,
  tone,
  pressed,
  testId,
}: {
  label: string
  onClick: () => void
  children: React.ReactNode
  tone?: 'danger' | 'accept'
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
        tone === 'danger' && 'bg-destructive text-destructive-foreground hover:bg-destructive/90',
        tone === 'accept' && 'bg-status-ok text-status-ok-foreground hover:bg-status-ok/90',
        !tone && (pressed ? 'bg-chrome-foreground text-chrome hover:bg-chrome-foreground/90' : 'bg-chrome-accent text-chrome-foreground hover:bg-chrome-active'),
      )}
      data-testid={testId}
    >
      {children}
    </Button>
  )
}
