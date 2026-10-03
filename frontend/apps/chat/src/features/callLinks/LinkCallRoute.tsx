import { Mic, MicOff, MonitorOff, MonitorUp, PhoneOff, Video, VideoOff } from 'lucide-react'
import { useEffect, useMemo, useState, useSyncExternalStore, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert } from '@kutup/ui/components/alert'
import { KutupLogo } from '@kutup/ui/components/brand'
import { Button } from '@kutup/ui/components/button'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { LoadingPanel } from '@kutup/ui/components/states'
import { canShareScreen, reportShareFailure } from '../calls/callController'
import { CallFrame, PanelButtons, RoundButton, type CallPanel, type CallPerson } from '../calls/CallFrame'
import { CallStage, type StageParticipant } from '../calls/CallStage'
import { LinkCallController, type LinkCallState } from '../calls/linkCallController'
import { openCallLink, type OpenCallLink } from './callLinks'
import { MAX_CALL_NAME_LENGTH, rememberCallName, rememberedCallName } from './callName'

/**
 * A call link, opened: `/call#<fragment>`. It needs no Kutup account, so it
 * sits outside the app's sign-in. The person chooses a name and joins; the
 * link's secret (in the fragment, which no server sees) gives the room, the
 * media key and the key the names are sealed under.
 */
export function LinkCallRoute() {
  const { t } = useTranslation()
  const [link, setLink] = useState<OpenCallLink | 'invalid' | null>(null)

  useEffect(() => {
    let current = true
    const open = () => {
      openCallLink(window.location.hash.slice(1))
        .then((opened) => current && setLink(opened))
        .catch(() => current && setLink('invalid'))
    }
    open()
    // Pasting another link into the address bar changes only the fragment.
    window.addEventListener('hashchange', open)
    return () => {
      current = false
      window.removeEventListener('hashchange', open)
    }
  }, [])

  if (link === null) return <LoadingPanel label={t('common.loading')} />
  if (link === 'invalid') {
    return (
      <main className="flex min-h-svh flex-col items-center justify-center gap-4 px-6 text-center">
        <KutupLogo size={40} />
        <h1 className="font-display text-2xl font-semibold tracking-tight">{t('chat.callLinks.invalidTitle')}</h1>
        <p className="max-w-md text-sm text-muted-foreground">{t('chat.callLinks.invalidDescription')}</p>
      </main>
    )
  }
  return <LinkCall key={link.roomId} link={link} />
}

function LinkCall({ link }: { link: OpenCallLink }) {
  const controller = useMemo(() => new LinkCallController(link), [link])
  useEffect(() => () => controller.dispose(), [controller])
  const call = useSyncExternalStore(controller.subscribe, controller.current)
  if (call && call.phase !== 'ended') return <InCall controller={controller} call={call} />
  return <JoinForm controller={controller} last={call} />
}

function JoinForm({ controller, last }: { controller: LinkCallController; last: LinkCallState | null }) {
  const { t } = useTranslation()
  const [name, setName] = useState(rememberedCallName)
  const [joining, setJoining] = useState(false)
  const trimmed = name.trim()

  async function join(withVideo: boolean) {
    if (!trimmed || joining) return
    setJoining(true)
    rememberCallName(trimmed)
    // The state says why a join failed; this page shows it below.
    await controller.join(trimmed, withVideo).catch(() => undefined)
    setJoining(false)
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    void join(false)
  }

  return (
    <main className="mx-auto flex min-h-svh w-full max-w-sm flex-col justify-center gap-6 px-6 py-10">
      <div className="flex flex-col items-center gap-3 text-center">
        <KutupLogo size={40} />
        <h1 className="font-display text-2xl font-semibold tracking-tight">{t('chat.callLinks.joinTitle')}</h1>
        <p className="text-sm text-muted-foreground">{t('chat.callLinks.joinDescription')}</p>
      </div>
      {last?.failure ? (
        <div data-testid="chat-link-call-failure" data-reason={last.failure}>
          <Alert variant="error">{t(`chat.callLinks.failed.${last.failure}`)}</Alert>
        </div>
      ) : last ? (
        <div data-testid="chat-link-call-left">
          <Alert variant="info">{t('chat.callLinks.left')}</Alert>
        </div>
      ) : null}
      <form onSubmit={submit} className="space-y-4">
        <Field label={t('chat.callLinks.name')} description={t('chat.callLinks.nameHint')} required>
          {(props) => (
            <Input
              {...props}
              autoFocus
              autoComplete="name"
              maxLength={MAX_CALL_NAME_LENGTH}
              value={name}
              onChange={(event) => setName(event.target.value)}
              data-testid="chat-link-call-name"
            />
          )}
        </Field>
        <div className="flex flex-col gap-2">
          <Button type="button" disabled={!trimmed || joining} onClick={() => void join(true)} data-testid="chat-link-call-join-video">
            <Video />
            {t('chat.callLinks.joinWithVideo')}
          </Button>
          <Button type="submit" variant="outline" disabled={!trimmed || joining} data-testid="chat-link-call-join">
            <Mic />
            {t('chat.callLinks.joinWithVoice')}
          </Button>
        </div>
      </form>
    </main>
  )
}

function InCall({ controller, call }: { controller: LinkCallController; call: LinkCallState }) {
  const { t } = useTranslation()
  const [panel, setPanel] = useState<CallPanel | null>(null)
  const participants: StageParticipant[] = call.participants.map((participant) => {
    const name = participant.local ? t('chat.you') : (participant.name ?? t('chat.callLinks.unnamed'))
    return { ...participant, name, avatarName: participant.name ?? name }
  })
  const people: CallPerson[] = participants.map((participant) => ({
    key: participant.identity,
    name: participant.name,
    avatarName: participant.avatarName,
    muted: participant.muted,
    cameraOn: participant.video !== null,
    sharing: participant.screen !== null,
  }))
  const status = call.phase === 'connecting' ? t('chat.calls.connecting') : t('chat.calls.inCall', { count: call.participants.length })

  return (
    <CallFrame
      label={t('chat.callLinks.callTitle')}
      title={t('chat.callLinks.callTitle')}
      status={status}
      phase={call.phase}
      testId="chat-link-call-screen"
      statusTestId="chat-link-call-status"
      people={people}
      // A link call has no conversation behind it: nothing to chat in.
      conversation={null}
      panel={panel}
      onPanel={setPanel}
      controls={
        <>
          <RoundButton label={call.muted ? t('chat.calls.unmute') : t('chat.calls.mute')} pressed={call.muted} onClick={() => controller.toggleMute()} testId="chat-link-call-mute">
            {call.muted ? <MicOff /> : <Mic />}
          </RoundButton>
          <RoundButton
            label={call.cameraOn ? t('chat.calls.cameraOff') : t('chat.calls.cameraOn')}
            pressed={!call.cameraOn}
            onClick={() => void controller.toggleCamera().catch((error: unknown) => console.warn('chat: the camera did not change', error))}
            testId="chat-link-call-camera"
          >
            {call.cameraOn ? <Video /> : <VideoOff />}
          </RoundButton>
          {canShareScreen() && call.phase === 'active' ? (
            <RoundButton
              label={call.screenOn ? t('chat.calls.stopSharing') : t('chat.calls.shareScreen')}
              pressed={call.screenOn}
              onClick={() => void controller.toggleScreen().catch((error: unknown) => reportShareFailure(error, t('chat.calls.shareFailed')))}
              testId="chat-link-call-screen-share"
            >
              {call.screenOn ? <MonitorOff /> : <MonitorUp />}
            </RoundButton>
          ) : null}
          <PanelButtons panel={panel} onPanel={setPanel} chat={false} />
          <RoundButton label={t('chat.calls.leave')} tone="danger" onClick={() => void controller.leave()} testId="chat-link-call-leave">
            <PhoneOff />
          </RoundButton>
        </>
      }
    >
      <CallStage participants={participants} />
    </CallFrame>
  )
}
