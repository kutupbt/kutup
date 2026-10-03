import { Mic, MicOff, MonitorOff, MonitorUp, Phone, PhoneOff, Video, VideoOff } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { cn } from '@kutup/ui/lib/cn'
import { getChatState, useChat } from '../../app/chatStore'
import { Avatar } from '@kutup/ui/components/avatar'
import { formatDuration } from '../../lib/callText'
import { personName } from '../../lib/names'
import { notificationsAllowed } from '../../lib/notificationPermission'
import { startRingtone } from '../../lib/ringtone'
import { useNow } from '../../lib/useNow'
import { getAlwaysRelayCalls, getNotifications } from '../../state/prefs'
import { parseAccountAddress } from '@kutup/chat-core/identity'
import type { ConversationId } from '@kutup/chat-core/types'
import { CallFrame, PanelButtons, RoundButton, type CallPanel, type CallPerson } from './CallFrame'
import { CallController, canShareScreen, reportShareFailure, type CallState } from './callController'
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
  const [panel, setPanel] = useState<CallPanel | null>(null)
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
  const peerAddress = parseAccountAddress(call.peer)
  // The conversation exists once the call was answered (calls ring only
  // between accepted contacts), so the chat opens then.
  const conversation: ConversationId | null = peerAddress && call.phase !== 'incoming' ? { kind: 'direct', address: peerAddress } : null
  const showRemoteVideo = remoteHasVideo && call.phase === 'active'
  const live = call.phase === 'outgoing' || call.phase === 'connecting' || call.phase === 'active'
  const people: CallPerson[] = [
    {
      key: 'self',
      name: t('chat.you'),
      avatarName: snapshot.profile?.displayName || self?.address || t('chat.you'),
      avatar: snapshot.profile?.avatar,
      avatarContentType: snapshot.profile?.avatarContentType,
      muted: call.muted,
      cameraOn: call.cameraOn,
      sharing: call.screenOn,
    },
    ...(call.phase === 'active'
      ? [{ key: 'peer', name, avatarName: name, avatar: profile?.avatar, avatarContentType: profile?.avatarContentType, cameraOn: remoteHasVideo, sharing: false }]
      : []),
  ]

  return (
    <CallFrame
      label={t('chat.calls.screen', { name })}
      title={name}
      status={status}
      phase={call.phase}
      testId="chat-call-screen"
      statusTestId="chat-call-status"
      people={people}
      conversation={conversation}
      panel={live ? panel : null}
      onPanel={setPanel}
      controls={
        call.phase === 'incoming' ? (
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
            {canShareScreen() && call.localStream ? (
              <RoundButton
                label={call.screenOn ? t('chat.calls.stopSharing') : t('chat.calls.shareScreen')}
                onClick={() => void act(() => controller?.toggleScreen().catch((error: unknown) => reportShareFailure(error, t('chat.calls.shareFailed'))))}
                pressed={call.screenOn}
                testId="chat-call-screen-share"
              >
                {call.screenOn ? <MonitorOff /> : <MonitorUp />}
              </RoundButton>
            ) : null}
            <PanelButtons panel={panel} onPanel={setPanel} chat={conversation !== null} />
            <RoundButton label={t('chat.calls.hangUp')} tone="danger" onClick={() => void act(() => controller?.hangUp())} testId="chat-call-hangup">
              <PhoneOff />
            </RoundButton>
          </>
        )
      }
    >
      <audio ref={remoteAudio} autoPlay />
      <div className="relative flex min-h-0 flex-1 items-center justify-center">
        <video
          ref={remoteVideo}
          autoPlay
          playsInline
          muted
          className={cn('absolute inset-0 size-full object-contain', !showRemoteVideo && 'invisible')}
          data-testid="chat-call-remote-video"
        />
        {!showRemoteVideo ? (
          <div className="flex flex-col items-center gap-3 text-center">
            <Avatar name={name} image={profile?.avatar} contentType={profile?.avatarContentType} size={80} />
            <p className="text-2xl font-semibold">{name}</p>
            <p className="text-sm text-stage-muted">{status}</p>
          </div>
        ) : null}
        {call.screenOn ? (
          <p className="absolute left-4 top-2 rounded bg-black/50 px-2 py-1 text-sm" data-testid="chat-call-sharing">
            {t('chat.calls.youAreSharing')}
          </p>
        ) : null}
        {(call.cameraOn || call.screenOn) && call.localStream ? (
          <video
            ref={localVideo}
            autoPlay
            playsInline
            muted
            className={cn(
              'absolute bottom-4 right-4 h-24 w-36 rounded-lg border border-white/20 bg-black md:h-32 md:w-48',
              // A camera shows as a mirror; a shared screen as it is.
              call.screenOn ? 'object-contain' : 'object-cover [transform:scaleX(-1)]',
            )}
            data-testid="chat-call-local-video"
            data-source={call.screenOn ? 'screen' : 'camera'}
          />
        ) : null}
      </div>
    </CallFrame>
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
