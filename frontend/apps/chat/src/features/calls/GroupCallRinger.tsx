import { Phone, PhoneOff, Video } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { ChatGroupCall } from '@kutup/chat-core/types'
import { Button } from '@kutup/ui/components/button'
import { useChat } from '../../app/chatStore'
import { Avatar } from '../../components/Avatar'
import { groupTitle, personName } from '../../lib/names'
import { notificationsAllowed } from '../../lib/notificationPermission'
import { startRingtone } from '../../lib/ringtone'
import { getNotifications } from '../../state/prefs'
import { callController, groupCallController, useCall, useGroupCall } from './callStore'

/** Groups this size or smaller ring when a call starts, as in Signal. */
const RING_GROUP_SIZE = 16
/** A start older than this does not ring. */
const RING_MS = 45_000

interface Ringing {
  groupId: string
  call: ChatGroupCall
  starter: string
  atMs: number
}

/**
 * Rings for a group call someone else just started in a small group: join,
 * join with video, or decline. One tab per account rings.
 */
export function GroupCallRinger() {
  const { t } = useTranslation()
  const { snapshot, self, loaded } = useChat()
  const oneToOne = useCall()
  const groupCall = useGroupCall()
  const inCall = oneToOne !== null || groupCall !== null
  const [ringing, setRinging] = useState<Ringing | null>(null)
  const seen = useRef<Set<string> | null>(null)

  useEffect(() => {
    if (!loaded) return
    const starts = snapshot.history.filter((entry) => entry.content.groupCall?.event === 'started')
    if (seen.current === null) {
      seen.current = new Set(starts.map((entry) => entry.content.groupCall!.callId))
      return
    }
    for (const entry of starts) {
      const call = entry.content.groupCall!
      if (seen.current.has(call.callId)) continue
      seen.current.add(call.callId)
      if (entry.direction !== 'incoming' || entry.conversation.kind !== 'group') continue
      if (Date.now() - entry.timestampMs > RING_MS || inCall || !callController()?.ringsHere) continue
      const group = snapshot.groups.find((g) => g.request.genesis.conversationId === (entry.conversation as { groupId: string }).groupId)
      if (!group || group.currentRoster.length > RING_GROUP_SIZE) continue
      setRinging({ groupId: group.request.genesis.conversationId, call, starter: entry.peer, atMs: entry.timestampMs })
    }
  }, [snapshot.history, snapshot.groups, loaded, inCall])

  // Stop ringing when the call ends, time runs out, or a call starts here.
  const ended = ringing !== null && snapshot.history.some(
    (entry) => entry.content.groupCall?.event === 'ended' && entry.content.groupCall.callId === ringing.call.callId,
  )
  useEffect(() => {
    if (!ringing) return
    if (ended || inCall) {
      setRinging(null)
      return
    }
    const timer = setTimeout(() => setRinging(null), Math.max(0, ringing.atMs + RING_MS - Date.now()))
    return () => clearTimeout(timer)
  }, [ringing, ended, inCall])

  const profiles = new Map(snapshot.profiles.map((p) => [p.peer, p]))
  const group = ringing ? snapshot.groups.find((g) => g.request.genesis.conversationId === ringing.groupId) : undefined
  const title = ringing ? groupTitle(ringing.groupId, t, group?.currentGroupInfo) : ''
  const starter = ringing ? personName(ringing.starter, profiles, self?.address ?? '', t) : ''

  useEffect(() => {
    if (!ringing) return
    const stop = startRingtone()
    let notification: Notification | null = null
    if (document.visibilityState !== 'visible' && getNotifications() && notificationsAllowed()) {
      notification = new Notification(title, {
        body: t('chat.calls.groupRinging', { name: starter }),
        tag: `kutup-group-call:${ringing.call.callId}`,
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
  }, [ringing, title, starter, t])

  if (!ringing) return null

  async function join(withVideo: boolean) {
    const target = ringing!
    setRinging(null)
    try {
      await groupCallController()?.join(target.groupId, target.call, withVideo)
    } catch (error) {
      toast.error(error instanceof DOMException && error.name === 'NotAllowedError'
        ? t('chat.calls.noDevices')
        : t('chat.calls.joinFailed'))
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex flex-col items-center justify-center gap-3 bg-stage text-center text-stage-foreground" role="dialog" aria-modal aria-label={t('chat.calls.groupScreen', { name: title })} data-testid="chat-group-call-ringing">
      <Avatar name={title} image={group?.currentGroupInfo?.avatar?.data} contentType={group?.currentGroupInfo?.avatar?.contentType} group size={80} />
      <h2 className="text-2xl font-semibold">{title}</h2>
      <p className="text-sm text-stage-muted">{t('chat.calls.groupRinging', { name: starter })}</p>
      <div className="mt-10 flex gap-4">
        <Button size="icon" className="size-14 rounded-full bg-destructive text-destructive-foreground hover:bg-destructive/90 [&_svg]:size-6" onClick={() => setRinging(null)} aria-label={t('chat.calls.decline')} title={t('chat.calls.decline')} data-testid="chat-group-call-decline">
          <PhoneOff />
        </Button>
        <Button size="icon" className="size-14 rounded-full bg-status-ok text-status-ok-foreground hover:bg-status-ok/90 [&_svg]:size-6" onClick={() => void join(false)} aria-label={t('chat.calls.join')} title={t('chat.calls.join')} data-testid="chat-group-call-answer">
          <Phone />
        </Button>
        {ringing.call.media === 'video' ? (
          <Button size="icon" className="size-14 rounded-full bg-status-ok text-status-ok-foreground hover:bg-status-ok/90 [&_svg]:size-6" onClick={() => void join(true)} aria-label={t('chat.calls.acceptVideo')} title={t('chat.calls.acceptVideo')} data-testid="chat-group-call-answer-video">
            <Video />
          </Button>
        ) : null}
      </div>
    </div>
  )
}
