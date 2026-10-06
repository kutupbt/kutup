import {
  BadgeCheck,
  CalendarPlus,
  DoorOpen,
  Loader2,
  Lock,
  LockOpen,
  LogOut,
  Mic,
  MicOff,
  MonitorOff,
  MonitorUp,
  MoreVertical,
  PhoneOff,
  ShieldCheck,
  ShieldOff,
  UserX,
  Video,
  VideoOff,
} from 'lucide-react'
import { useEffect, useMemo, useRef, useState, useSyncExternalStore, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { refreshAccessToken } from '@kutup/session/client'
import { readPersisted } from '@kutup/session/persistedStore'
import { Alert } from '@kutup/ui/components/alert'
import { KutupLogo } from '@kutup/ui/components/brand'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@kutup/ui/components/dropdown-menu'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { LoadingPanel } from '@kutup/ui/components/states'
import { canShareScreen, reportShareFailure } from '../calls/callController'
import { CallFrame, PanelButtons, RoundButton, type CallPanel, type CallPerson } from '../calls/CallFrame'
import { CallStage, type StageParticipant } from '../calls/CallStage'
import { LinkCallController, type LinkCallState } from '../calls/linkCallController'
import { CallLinkRefused, fetchMeetingInfo, openCallLink, type CallLinkRefusal, type MeetingInfo, type MeetingRole, type OpenCallLink } from './callLinks'
import { MAX_CALL_NAME_LENGTH, rememberCallName, rememberedCallName } from './callName'
import { hostTokenFor } from './hostTokens'
import { downloadMeetingIcs } from './ics'
import { MeetingChat } from './MeetingChat'
import { recordJoinedMeeting } from './meetingHistory'
import { meetingStartText } from './meetingTime'

/**
 * A meeting link, opened: `/call#<fragment>`. It needs no Kutup account, so
 * it sits outside the app's sign-in. The page shows what the meeting is
 * called and when it is; the person chooses a name and joins. The link's
 * secret (in the fragment, which no server sees) gives the room, the media
 * key, and the keys the names, the details and the chat are sealed under.
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

/**
 * The account signed in to Kutup in this browser, if any. This page has no
 * session of its own; it only knows that one is kept here, and can ask for
 * an access token with it when the person wants their account shown.
 */
function signedInAccount(): string | null {
  return readPersisted()?.userId ?? null
}

function LinkCall({ link }: { link: OpenCallLink }) {
  const { t } = useTranslation()
  // The owner's proof of being the host, when they are signed in here.
  const controller = useMemo(() => new LinkCallController(link, hostTokenFor(link.roomId)), [link])
  useEffect(() => () => controller.dispose(), [controller])
  const call = useSyncExternalStore(controller.subscribe, controller.current)
  // What the meeting is called, when it is and whether joiners wait to be
  // let in: asked before joining, and again after each stay (a host who
  // removes someone turns the waiting room on).
  const [info, setInfo] = useState<Meeting | CallLinkRefusal | null>(null)
  const stayed = call?.phase === 'ended'
  useEffect(() => {
    let current = true
    fetchMeetingInfo(link)
      .then((fetched) => current && setInfo(fetched))
      .catch((error: unknown) => current && setInfo(error instanceof CallLinkRefused ? error.reason : 'unavailable'))
    return () => {
      current = false
    }
  }, [link, stayed])
  const title = typeof info === 'object' && info ? info.info.title : t('chat.meetings.defaultTitle')

  // Each stay goes into the list of joined meetings of the account signed
  // in here, when it ends. Without an account there is no such list.
  const active = call?.phase === 'active'
  const wasActive = useRef(false)
  useEffect(() => {
    if (active) {
      wasActive.current = true
      return
    }
    if (!wasActive.current || call?.phase !== 'ended') return
    wasActive.current = false
    const account = signedInAccount()
    if (!account) return
    const { atMs, seconds } = controller.joined
    recordJoinedMeeting({ fragment: link.fragment, roomId: link.roomId, title, joinedAtMs: atMs, seconds }, account)
  }, [active, call?.phase, controller, link, title])

  if (info === null) return <LoadingPanel label={t('common.loading')} />
  if (call?.phase === 'waiting') return <Waiting controller={controller} title={title} />
  if (call && call.phase !== 'ended') return <InCall controller={controller} call={call} title={title} />
  return <JoinForm controller={controller} last={call} link={link} info={info} />
}

/** What the page learned of the meeting before joining. */
interface Meeting {
  info: MeetingInfo
  waitingRoom: boolean
  locked: boolean
}

/** Knocked, and waiting for a host to let this browser in. */
function Waiting({ controller, title }: { controller: LinkCallController; title: string }) {
  const { t } = useTranslation()
  return (
    <main className="mx-auto flex min-h-svh w-full max-w-sm flex-col items-center justify-center gap-5 px-6 py-10 text-center" data-testid="chat-link-call-waiting">
      <KutupLogo size={40} />
      <h1 className="font-display text-2xl font-semibold tracking-tight">{title}</h1>
      <p className="flex items-center gap-2 text-sm font-medium">
        <Loader2 className="size-4 animate-spin" aria-hidden />
        {t('chat.meetings.waiting')}
      </p>
      <p className="text-sm text-muted-foreground">{t('chat.meetings.waitingDescription')}</p>
      <Button type="button" variant="outline" onClick={() => void controller.leave()} data-testid="chat-link-call-waiting-cancel">
        {t('common.cancel')}
      </Button>
    </main>
  )
}

const SHOW_ACCOUNT_KEY = 'kutup-meeting-show-account'

function rememberedShowAccount(): boolean {
  try {
    return localStorage.getItem(SHOW_ACCOUNT_KEY) !== '0'
  } catch {
    return true
  }
}

function JoinForm({
  controller,
  last,
  link,
  info,
}: {
  controller: LinkCallController
  last: LinkCallState | null
  link: OpenCallLink
  info: Meeting | CallLinkRefusal
}) {
  const { t, i18n } = useTranslation()
  const [name, setName] = useState(rememberedCallName)
  const [joining, setJoining] = useState(false)
  // Someone signed in here can show the others their account, which the
  // server vouches for; a name alone is only what was typed.
  const signedIn = useMemo(signedInAccount, [])
  const [showAccount, setShowAccount] = useState(rememberedShowAccount)
  const trimmed = name.trim()
  const meeting = typeof info === 'object' ? info.info : null
  // Whether pressing Join knocks: a waiting room, and not the owner.
  const knocks = typeof info === 'object' && info.waitingRoom && !controller.isOwner
  const locked = typeof info === 'object' && info.locked && !controller.isOwner
  // The link itself was refused (deleted, say): nothing to join.
  const refused = typeof info === 'string' ? info : null
  const failure = last?.failure ?? refused ?? (locked ? 'locked' : null)

  async function join(withVideo: boolean) {
    if (!trimmed || joining) return
    setJoining(true)
    rememberCallName(trimmed)
    try {
      localStorage.setItem(SHOW_ACCOUNT_KEY, showAccount ? '1' : '0')
    } catch {
      // Private browsing: asked again next time.
    }
    // The state says why a join failed; this page shows it below.
    await controller
      .join(trimmed, {
        withVideo,
        waitingRoom: typeof info === 'object' && info.waitingRoom,
        vouchFor: signedIn && showAccount ? async () => (await refreshAccessToken()).accessToken : undefined,
      })
      .catch(() => undefined)
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
        <h1 className="font-display text-2xl font-semibold tracking-tight" data-testid="chat-link-call-title">
          {meeting ? meeting.title : t('chat.callLinks.joinTitle')}
        </h1>
        {meeting?.startsAtMs !== undefined ? (
          <p className="text-sm font-medium" data-testid="chat-link-call-when">
            {meeting.durationMinutes
              ? t('chat.meetings.whenWithLength', {
                  when: meetingStartText(meeting.startsAtMs, i18n.language),
                  length: t('chat.meetings.minutes', { count: meeting.durationMinutes }),
                })
              : meetingStartText(meeting.startsAtMs, i18n.language)}
          </p>
        ) : null}
        <p className="text-sm text-muted-foreground">{t('chat.callLinks.joinDescription')}</p>
        {knocks ? (
          <p className="flex items-center gap-2 text-sm font-medium" data-testid="chat-link-call-has-waiting-room">
            <DoorOpen className="size-4" aria-hidden />
            {t('chat.meetings.hasWaitingRoom')}
          </p>
        ) : null}
        {meeting?.startsAtMs !== undefined ? (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => downloadMeetingIcs({ roomId: link.roomId, url: window.location.href, info: meeting })}
            data-testid="chat-link-call-ics"
          >
            <CalendarPlus />
            {t('chat.meetings.addToCalendar')}
          </Button>
        ) : null}
      </div>
      {failure ? (
        <div data-testid="chat-link-call-failure" data-reason={failure}>
          <Alert variant="error">{t(`chat.callLinks.failed.${failure}`)}</Alert>
        </div>
      ) : last?.wasIn ? (
        <div data-testid="chat-link-call-left">
          <Alert variant="info">{t('chat.callLinks.left')}</Alert>
        </div>
      ) : null}
      {refused === 'gone' ? null : (
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
          {signedIn ? (
            <div className="space-y-1">
              <label className="flex items-center gap-2 text-sm">
                <Checkbox checked={showAccount} onCheckedChange={(checked) => setShowAccount(checked === true)} data-testid="chat-link-call-show-account" />
                {t('chat.meetings.showAccount')}
              </label>
              <p className="pl-6 text-xs text-muted-foreground">{t('chat.meetings.showAccountHint')}</p>
            </div>
          ) : null}
          <div className="flex flex-col gap-2">
            <Button type="button" disabled={!trimmed || joining} onClick={() => void join(true)} data-testid="chat-link-call-join-video">
              <Video />
              {knocks ? t('chat.meetings.askWithVideo') : t('chat.callLinks.joinWithVideo')}
            </Button>
            <Button type="submit" variant="outline" disabled={!trimmed || joining} data-testid="chat-link-call-join">
              <Mic />
              {knocks ? t('chat.meetings.askWithVoice') : t('chat.callLinks.joinWithVoice')}
            </Button>
          </div>
        </form>
      )}
    </main>
  )
}

function InCall({ controller, call, title }: { controller: LinkCallController; call: LinkCallState; title: string }) {
  const { t } = useTranslation()
  const [panel, setPanel] = useState<CallPanel | null>(null)
  // Messages that arrived while the chat was closed.
  const [seen, setSeen] = useState(0)
  useEffect(() => {
    if (panel === 'chat') setSeen(call.messages.length)
  }, [panel, call.messages.length])
  const unread = panel !== 'chat' && call.messages.slice(seen).some((message) => !message.own)

  // What a host did to this browser, and what it became, said once each.
  useEffect(() => {
    if (call.mutedByHost > 0) toast.message(t('chat.meetings.mutedByHost'))
  }, [call.mutedByHost, t])
  const couldShare = useRef(call.canShare)
  useEffect(() => {
    if (couldShare.current && !call.canShare) toast.message(t('chat.meetings.shareStopped'))
    couldShare.current = call.canShare
  }, [call.canShare, t])
  const lastRole = useRef<MeetingRole | null>(call.role)
  useEffect(() => {
    if (call.role === 'coHost' && lastRole.current !== 'coHost') toast.message(t('chat.meetings.nowCoHost'))
    lastRole.current = call.role
  }, [call.role, t])

  /** A host's action whose failure is told, not thrown. */
  function act(work: () => Promise<void>, failed: string) {
    void work().catch(() => toast.error(failed))
  }
  // What a host is being asked to confirm: removing someone, or ending the
  // meeting for everyone.
  const [confirming, setConfirming] = useState<{ remove: { identity: string; name: string } } | 'end' | null>(null)
  const [pending, setPending] = useState(false)
  const [failed, setFailed] = useState<unknown>(null)
  function ask(what: typeof confirming) {
    setFailed(null)
    setConfirming(what)
  }
  async function confirmed(work: () => Promise<void>) {
    setPending(true)
    setFailed(null)
    try {
      await work()
      setConfirming(null)
    } catch (error) {
      setFailed(error)
    } finally {
      setPending(false)
    }
  }
  const owner = call.role === 'owner'
  const host = call.role !== null
  const participants: (StageParticipant & { role: MeetingRole | null; account: string; canShare: boolean })[] = call.participants.map((participant) => {
    const name = participant.local ? t('chat.you') : (participant.name ?? t('chat.callLinks.unnamed'))
    return { ...participant, name, avatarName: participant.name ?? name }
  })
  const people: CallPerson[] = participants.map((participant) => ({
    key: participant.identity,
    name: participant.name,
    avatarName: participant.avatarName,
    account: participant.account || undefined,
    muted: participant.muted,
    cameraOn: participant.video !== null,
    sharing: participant.screen !== null,
    badge: participant.role === 'owner' ? t('chat.meetings.roleOwner') : participant.role === 'coHost' ? t('chat.meetings.roleCoHost') : undefined,
    actions:
      // The owner acts on anyone else; a co-host on those who are not hosts.
      !participant.local && host && participant.role !== 'owner' && (owner || participant.role === null) ? (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="shrink-0"
              aria-label={t('chat.meetings.personActions', { name: participant.name })}
              data-testid="chat-meeting-person-menu"
            >
              <MoreVertical />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            {participant.muted ? null : (
              <DropdownMenuItem onSelect={() => act(() => controller.mute(participant.identity), t('chat.meetings.muteFailed'))} data-testid="chat-meeting-mute">
                <MicOff />
                {t('chat.meetings.mute')}
              </DropdownMenuItem>
            )}
            <DropdownMenuItem
              onSelect={() => act(() => controller.setScreenShare(participant.identity, !participant.canShare), t('chat.meetings.screenFailed'))}
              data-testid="chat-meeting-screen"
            >
              {participant.canShare ? <MonitorOff /> : <MonitorUp />}
              {participant.canShare ? t('chat.meetings.stopSharing') : t('chat.meetings.allowSharing')}
            </DropdownMenuItem>
            {owner ? (
              <DropdownMenuItem
                onSelect={() => act(() => controller.setCoHost(participant.identity, participant.role !== 'coHost'), t('chat.meetings.coHostFailed'))}
                data-testid="chat-meeting-co-host"
              >
                {participant.role === 'coHost' ? <ShieldOff /> : <ShieldCheck />}
                {participant.role === 'coHost' ? t('chat.meetings.removeCoHost') : t('chat.meetings.makeCoHost')}
              </DropdownMenuItem>
            ) : null}
            <DropdownMenuSeparator />
            <DropdownMenuItem
              destructive
              onSelect={() => ask({ remove: { identity: participant.identity, name: participant.name } })}
              data-testid="chat-meeting-remove"
            >
              <UserX />
              {t('chat.meetings.remove')}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ) : undefined,
  }))
  const removing = confirming !== null && confirming !== 'end' ? confirming.remove : null
  const status = call.phase === 'connecting' ? t('chat.calls.connecting') : t('chat.calls.inCall', { count: call.participants.length })

  return (
    <CallFrame
      label={t('chat.calls.screen', { name: title })}
      title={title}
      status={status}
      phase={call.phase}
      testId="chat-link-call-screen"
      statusTestId="chat-link-call-status"
      people={people}
      peopleActions={
        host ? (
          <>
            <Button size="sm" variant="outline" onClick={() => act(() => controller.muteAll(), t('chat.meetings.muteFailed'))} data-testid="chat-meeting-mute-all">
              <MicOff />
              {t('chat.meetings.muteAll')}
            </Button>
            <Button
              size="sm"
              variant="outline"
              aria-pressed={call.locked}
              onClick={() => act(() => controller.setLocked(!call.locked), t('chat.meetings.lockFailed'))}
              data-testid="chat-meeting-lock"
              data-locked={call.locked}
            >
              {call.locked ? <LockOpen /> : <Lock />}
              {call.locked ? t('chat.meetings.unlock') : t('chat.meetings.lock')}
            </Button>
          </>
        ) : call.locked ? (
          <p className="flex items-center gap-2 px-1 text-xs text-muted-foreground" data-testid="chat-meeting-locked">
            <Lock className="size-3.5" aria-hidden />
            {t('chat.meetings.isLocked')}
          </p>
        ) : null
      }
      chat={<MeetingChat messages={call.messages} onSend={(text) => controller.send(text)} />}
      panel={panel}
      onPanel={setPanel}
      controls={
        <>
          <RoundButton
            label={call.muted ? t('chat.calls.unmute') : t('chat.calls.mute')}
            pressed={call.muted}
            onClick={() => void controller.toggleMute().catch((error: unknown) => console.warn('chat: the microphone did not change', error))}
            testId="chat-link-call-mute"
          >
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
              label={!call.canShare ? t('chat.meetings.shareStopped') : call.screenOn ? t('chat.calls.stopSharing') : t('chat.calls.shareScreen')}
              pressed={call.screenOn}
              disabled={!call.canShare}
              onClick={() => void controller.toggleScreen().catch((error: unknown) => reportShareFailure(error, t('chat.calls.shareFailed')))}
              testId="chat-link-call-screen-share"
            >
              {call.screenOn ? <MonitorOff /> : <MonitorUp />}
            </RoundButton>
          ) : null}
          <PanelButtons panel={panel} onPanel={setPanel} chat unread={unread} />
          {owner ? (
            // The owner chooses: leave the others to it, or end it for all.
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <RoundButton label={t('chat.calls.leave')} tone="danger" testId="chat-link-call-leave-menu">
                  <PhoneOff />
                </RoundButton>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="center" side="top">
                <DropdownMenuItem onSelect={() => void controller.leave()} data-testid="chat-link-call-leave">
                  <LogOut />
                  {t('chat.meetings.leave')}
                </DropdownMenuItem>
                <DropdownMenuItem destructive onSelect={() => ask('end')} data-testid="chat-meeting-end">
                  <PhoneOff />
                  {t('chat.meetings.endForAll')}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          ) : (
            <RoundButton label={t('chat.calls.leave')} tone="danger" onClick={() => void controller.leave()} testId="chat-link-call-leave">
              <PhoneOff />
            </RoundButton>
          )}
        </>
      }
    >
      <ConfirmDestructive
        open={removing !== null}
        onOpenChange={(open) => !open && setConfirming(null)}
        title={t('chat.meetings.removeTitle', { name: removing?.name ?? '' })}
        description={t('chat.meetings.removeDescription', { name: removing?.name ?? '' })}
        warning={t('chat.meetings.removeWarning')}
        warningVariant="warn"
        submit={t('chat.meetings.remove')}
        pending={pending}
        error={failed}
        errorFallback={t('chat.meetings.removeFailed')}
        onConfirm={() => removing && void confirmed(() => controller.remove(removing.identity))}
      />
      <ConfirmDestructive
        open={confirming === 'end'}
        onOpenChange={(open) => !open && setConfirming(null)}
        title={t('chat.meetings.endTitle')}
        description={t('chat.meetings.endDescription')}
        submit={t('chat.meetings.endSubmit')}
        pending={pending}
        error={failed}
        errorFallback={t('chat.meetings.endFailed')}
        onConfirm={() => void confirmed(() => controller.endForAll())}
      />
      <CallStage participants={participants} />
      {call.waiting.length > 0 ? (
        <aside
          className="absolute right-3 top-3 z-10 w-72 max-w-[calc(100%-1.5rem)] space-y-2 rounded-xl border border-border bg-background p-3 text-foreground shadow-lg"
          aria-label={t('chat.meetings.waitingTitle', { count: call.waiting.length })}
          data-testid="chat-meeting-knocks"
        >
          <div className="flex items-center gap-2">
            <p className="min-w-0 flex-1 text-sm font-semibold">{t('chat.meetings.waitingTitle', { count: call.waiting.length })}</p>
            {call.waiting.length > 1 ? (
              <Button size="sm" variant="ghost" onClick={() => act(() => controller.admitAll(), t('chat.meetings.decideFailed'))} data-testid="chat-meeting-admit-all">
                {t('chat.meetings.admitAll')}
              </Button>
            ) : null}
          </div>
          <ul className="max-h-60 space-y-2 overflow-y-auto">
            {call.waiting.map((person) => (
              <li key={person.knockId} className="space-y-1.5" data-testid="chat-meeting-knock" data-name={person.name ?? ''}>
                <p className="truncate text-sm">{person.name ?? t('chat.callLinks.unnamed')}</p>
                {person.account ? (
                  <p className="flex min-w-0 items-center gap-1 text-xs text-muted-foreground" data-testid="chat-meeting-knock-account">
                    <BadgeCheck className="size-3.5 shrink-0 text-primary" aria-label={t('chat.calls.verifiedAccount')} />
                    <span className="min-w-0 truncate">{person.account}</span>
                  </p>
                ) : null}
                <div className="flex gap-2">
                  {/* Already decided, or the person stopped waiting: the list catches up. */}
                  <Button size="sm" onClick={() => act(() => controller.admit(person.knockId), t('chat.meetings.decideFailed'))} data-testid="chat-meeting-admit">
                    {t('chat.meetings.admit')}
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => act(() => controller.turnAway(person.knockId), t('chat.meetings.decideFailed'))}
                    data-testid="chat-meeting-turn-away"
                  >
                    {t('chat.meetings.turnAway')}
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        </aside>
      ) : null}
    </CallFrame>
  )
}
