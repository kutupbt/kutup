import { Link2, Users } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import type { OwnJoinRequest, PendingMlsInvitation } from '@kutup/chat-core/types'
import { Button } from '@kutup/ui/components/button'
import { refreshChat, useChat } from '../../app/chatStore'
import { chatErrorMessage } from '../../lib/errors'
import { groupTitle } from '../../lib/names'
import { pathForConversation } from './paths'

/**
 * Groups this account was invited to, and those it asked to join through a
 * link, above the conversations.
 */
export function GroupInvitations() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { service, snapshot } = useChat()
  const [busy, setBusy] = useState<string | null>(null)
  // An invitation a request led to is accepted by itself: not listed twice.
  const requested = new Set(
    snapshot.ownJoinRequests
      .filter((request) => request.status === 'pending')
      .map((request) => request.conversationId),
  )
  const invitations = snapshot.invitations.filter((invitation) => !requested.has(invitation.conversationId))
  const ownRequests = snapshot.ownJoinRequests
  if (invitations.length === 0 && ownRequests.length === 0) return null

  async function withdraw(request: OwnJoinRequest) {
    if (!service) return
    setBusy(request.linkId)
    try {
      await service.cancelJoinRequest(request.linkId)
      await refreshChat()
    } catch (error) {
      toast.error(chatErrorMessage(error, t))
    } finally {
      setBusy(null)
    }
  }

  async function respond(invitation: PendingMlsInvitation, accept: boolean) {
    if (!service) return
    setBusy(invitation.conversationId)
    try {
      if (accept) await service.acceptGroupInvitation(invitation)
      else await service.rejectGroupInvitation(invitation)
      await refreshChat()
      if (accept) void navigate(pathForConversation({ kind: 'group', groupId: invitation.conversationId }))
    } catch (error) {
      toast.error(chatErrorMessage(error, t))
    } finally {
      setBusy(null)
    }
  }

  return (
    <>
    {ownRequests.length > 0 ? (
      <section className="mx-2 mt-2 rounded-[10px] border border-border bg-muted/40 p-3" data-testid="chat-own-join-requests" aria-labelledby="own-join-requests-title">
        <h2 id="own-join-requests-title" className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          {t('chat.groupLink.ownRequestsTitle', { count: ownRequests.length })}
        </h2>
        <ul className="space-y-2">
          {ownRequests.map((request) => (
            <li key={request.linkId} className="flex items-center gap-2">
              <Link2 className="size-4 shrink-0 text-muted-foreground" aria-hidden />
              <span className="min-w-0 flex-1">
                <span className="block truncate text-sm">{request.groupName}</span>
                <span className="block truncate text-xs text-muted-foreground">
                  {t(`chat.groupLink.ownStatus.${request.status}`)}
                </span>
              </span>
              <Button size="sm" variant="ghost" disabled={busy !== null} onClick={() => void withdraw(request)} data-testid="chat-own-join-request-cancel">
                {request.status === 'pending' ? t('chat.groupLink.cancelRequest') : t('chat.groupLink.dismiss')}
              </Button>
            </li>
          ))}
        </ul>
      </section>
    ) : null}
    {invitations.length > 0 ? (
    <section className="mx-2 mt-2 rounded-[10px] border border-primary/30 bg-accent/40 p-3" data-testid="chat-group-invitations" aria-labelledby="group-invitations-title">
      <h2 id="group-invitations-title" className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {t('chat.groupInvitations.title', { count: invitations.length })}
      </h2>
      <ul className="space-y-2">
        {invitations.map((invitation) => (
          <li key={`${invitation.conversationId}:${invitation.incarnation}`} className="flex items-center gap-2">
            <Users className="size-4 shrink-0 text-muted-foreground" aria-hidden />
            <span className="min-w-0 flex-1 truncate text-sm">{groupTitle(invitation.conversationId, t)}</span>
            <Button size="sm" variant="ghost" disabled={busy !== null} onClick={() => void respond(invitation, false)}>
              {t('chat.requests.reject')}
            </Button>
            <Button size="sm" disabled={busy !== null} onClick={() => void respond(invitation, true)} data-testid="chat-group-accept">
              {t('chat.requests.accept')}
            </Button>
          </li>
        ))}
      </ul>
    </section>
    ) : null}
    </>
  )
}
