import { CloudOff, ShieldAlert, UserX } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { ChatGroupSync } from '@kutup/chat-core/types'
import { refreshChat, useChat } from '../../app/chatStore'
import type { ConversationModel } from './useConversationModel'

/**
 * A pairwise group's standing with its home (docs/plans/pairwise-groups.md
 * §3), above its thread: caught up when the group opens, and saying so when
 * the home can't be reached, may have removed this account, or may be
 * showing members different keys or histories. Never hidden: messages still
 * go through, but the person should know.
 */
export function ChatGroupStatus({ model }: { model: ConversationModel }) {
  const { t } = useTranslation()
  const { service } = useChat()
  const [sync, setSync] = useState<ChatGroupSync | null>(null)
  const groupId = model.chatGroup?.status === 'member' ? model.chatGroup.groupId : null
  const requesting = model.chatGroup?.status === 'requesting' ? model.chatGroup.groupId : null

  // A request is settled when its group opens: approved ones join, denied
  // ones end (the home tells nobody, so this device asks).
  useEffect(() => {
    if (!service || !requesting) return
    let current = true
    service
      .checkChatGroupRequest(requesting)
      .then((outcome) => {
        if (!current) return
        if (outcome.kind === 'denied') toast.message(t('chat.chatGroupLink.denied'))
        if (outcome.kind !== 'pending' && outcome.kind !== 'unreachable') void refreshChat()
      })
      .catch((error: unknown) => console.warn('chat: the request to join could not be checked', error))
    return () => {
      current = false
    }
  }, [service, requesting, t])

  useEffect(() => {
    setSync(null)
    if (!service || !groupId) return
    let current = true
    service
      .syncChatGroup(groupId)
      .then((result) => {
        if (!current) return
        setSync(result)
        void refreshChat()
      })
      .catch((error: unknown) => console.warn('chat: the group could not be caught up', error))
    return () => {
      current = false
    }
  }, [service, groupId])

  if (!groupId) return null
  const notices: { key: string; icon: typeof ShieldAlert; text: string; tone: 'warning' | 'muted' }[] = []
  if (sync?.kind === 'current' && !sync.keyConfirmed) {
    notices.push({ key: 'keys', icon: ShieldAlert, text: t('chat.chatGroup.keyUnconfirmed'), tone: 'warning' })
  }
  if (model.chatGroup?.forkSuspected) {
    notices.push({ key: 'fork', icon: ShieldAlert, text: t('chat.chatGroup.forkSuspected'), tone: 'warning' })
  }
  if (sync?.kind === 'maybeRemoved') {
    notices.push({ key: 'removed', icon: UserX, text: t('chat.chatGroup.maybeRemoved'), tone: 'warning' })
  }
  if (sync?.kind === 'unreachable') {
    notices.push({ key: 'unreachable', icon: CloudOff, text: t('chat.chatGroup.unreachable'), tone: 'muted' })
  }
  if (notices.length === 0) return null
  return (
    <div className="flex flex-col gap-1 border-b border-border px-4 py-2" data-testid="chat-group-status">
      {notices.map(({ key, icon: Icon, text, tone }) => (
        <p
          key={key}
          role={tone === 'warning' ? 'alert' : 'status'}
          className={
            tone === 'warning'
              ? 'flex items-start gap-2 text-sm text-destructive'
              : 'flex items-start gap-2 text-sm text-muted-foreground'
          }
        >
          <Icon className="mt-0.5 size-4 shrink-0" aria-hidden />
          {text}
        </p>
      ))}
    </div>
  )
}
