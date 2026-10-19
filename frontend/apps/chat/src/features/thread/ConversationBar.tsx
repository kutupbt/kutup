import { Ban, Clock, DoorOpen, Lock, ShieldAlert } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { Button } from '@kutup/ui/components/button'
import { refreshChat, useChat } from '../../app/chatStore'
import { chatErrorMessage } from '../../lib/errors'
import { personName } from '../../lib/names'
import { accountName } from '../../state/accountNames'
import type { ConversationModel } from './useConversationModel'

/**
 * Text someone else chose (a stranger's name, a group's title), set inside a
 * sentence as its own direction-isolated run (U+2068 … U+2069), so its
 * bidirectional controls can't reorder the words around it.
 */
function isolate(text: string): string {
  return `\u2068${text}\u2069`
}

/**
 * What stands where the composer would when nothing can be written, as in
 * Signal: a message request's Accept / Reject / Block, a blocked contact's
 * Unblock, or why a group is read-only.
 */
export function ConversationBar({ model }: { model: ConversationModel }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { service, snapshot, self } = useChat()
  const [busy, setBusy] = useState(false)
  const peer = model.peer

  /** An invitation to a pairwise group: join, decline, or block its sender. */
  async function answerInvitation(action: 'join' | 'decline' | 'block') {
    const groupId = model.chatGroup?.groupId
    if (!service || !groupId) return
    setBusy(true)
    try {
      if (action === 'join') {
        const joined = await service.acceptChatGroupInvite(groupId)
        if (joined.kind === 'unreachable') toast.error(t('chat.chatGroup.unreachable'))
        else if (joined.kind !== 'current' && joined.kind !== 'partial') toast.error(t('chat.chatGroup.invitationGone'))
      } else if (action === 'block' && model.groupInviter) {
        // Blocked first, so nothing more from them lands meanwhile; then
        // every invitation of theirs goes, not just this one.
        const inviter = model.groupInviter
        await service.blockContact(inviter)
        const theirs = snapshot.chatGroups.filter((group) => group.status === 'invited' && group.inviter === inviter)
        for (const group of theirs) await service.declineChatGroupInvite(group.groupId)
        if (!theirs.some((group) => group.groupId === groupId)) await service.declineChatGroupInvite(groupId)
      } else {
        await service.declineChatGroupInvite(groupId)
      }
      await refreshChat()
      if (action !== 'join') void navigate('/')
    } catch (error) {
      toast.error(chatErrorMessage(error, t))
    } finally {
      setBusy(false)
    }
  }

  async function update(action: 'accept' | 'reject' | 'block' | 'unblock') {
    if (!service || !peer) return
    setBusy(true)
    try {
      if (action === 'accept') await service.acceptContact(peer)
      else if (action === 'reject') await service.rejectContact(peer)
      else if (action === 'block') await service.blockContact(peer)
      else await service.unblockContact(peer)
      await refreshChat()
      if (action === 'reject') void navigate('/')
    } catch (error) {
      toast.error(chatErrorMessage(error, t))
    } finally {
      setBusy(false)
    }
  }

  const frame = 'border-t border-border px-4 py-3'
  switch (model.readOnly) {
    case 'request':
      return (
        <div className={frame}>
          <p className="text-center text-sm">
            <span className="font-semibold">{t('chat.requests.incoming', { peer: model.title })}</span>
          </p>
          <p className="mt-1 text-center text-xs text-muted-foreground">{t('chat.requests.description')}</p>
          <div className="mt-3 flex flex-wrap justify-center gap-2">
            <Button variant="outline" disabled={busy} onClick={() => void update('block')}>
              {t('chat.requests.block')}
            </Button>
            <Button variant="outline" disabled={busy} onClick={() => void update('reject')}>
              {t('chat.requests.reject')}
            </Button>
            <Button disabled={busy} onClick={() => void update('accept')}>
              {t('chat.requests.accept')}
            </Button>
          </div>
        </div>
      )
    case 'invitation': {
      const profiles = new Map(snapshot.profiles.map((profile) => [profile.peer, profile]))
      const inviter = model.groupInviter ? personName(model.groupInviter, profiles, self?.key ?? '', t) : t('chat.someone')
      // Someone who isn't a contact is shown by the address their name
      // could imitate, too.
      const address = model.groupInviteRequest && model.groupInviter ? accountName(model.groupInviter) : null
      return (
        <div className={frame} data-testid="chat-group-invitation">
          <p className="text-center text-sm">
            <span className="font-semibold">{t('chat.chatGroup.invited', { name: isolate(inviter), group: isolate(model.title) })}</span>
          </p>
          {address && address !== inviter ? (
            <p className="text-center text-xs text-muted-foreground" dir="auto" data-testid="chat-group-inviter-address">
              {address}
            </p>
          ) : null}
          <p className="mt-1 text-center text-xs text-muted-foreground">
            {t(model.groupInviteRequest ? 'chat.chatGroup.invitedRequest' : 'chat.chatGroup.invitedDescription')}
          </p>
          <div className="mt-3 flex flex-wrap justify-center gap-2">
            {model.groupInviteRequest ? (
              <Button variant="outline" disabled={busy} onClick={() => void answerInvitation('block')}>
                {t('chat.requests.block')}
              </Button>
            ) : null}
            <Button variant="outline" disabled={busy} onClick={() => void answerInvitation('decline')}>
              {t('chat.chatGroup.decline')}
            </Button>
            <Button disabled={busy} onClick={() => void answerInvitation('join')}>
              {t('chat.chatGroup.join')}
            </Button>
          </div>
        </div>
      )
    }
    case 'blocked':
      return (
        <div className={frame}>
          <p className="flex items-center justify-center gap-1.5 text-center text-sm text-muted-foreground">
            <Ban className="size-4" aria-hidden />
            {t('chat.requests.blocked', { peer: model.title })}
          </p>
          <div className="mt-3 flex justify-center">
            <Button variant="outline" disabled={busy} onClick={() => void update('unblock')}>
              {t('chat.requests.unblock')}
            </Button>
          </div>
        </div>
      )
    default: {
      const Icon =
        model.readOnly === 'pendingInvitations'
          ? Clock
          : model.readOnly === 'adminsOnly'
            ? ShieldAlert
            : model.readOnly === 'left'
              ? DoorOpen
              : Lock
      return (
        <div className={frame} data-testid={model.readOnly === 'pendingInvitations' ? 'chat-group-delivery-readiness' : undefined}>
          <p className="flex items-center justify-center gap-1.5 text-center text-sm text-muted-foreground">
            <Icon className="size-4 shrink-0" aria-hidden />
            {t(`chat.readOnly.${model.readOnly}`, { count: model.readiness.pending.length })}
          </p>
        </div>
      )
    }
  }
}
