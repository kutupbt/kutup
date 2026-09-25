import { Link2 } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { LocalMlsConversationRecord } from '@kutup/chat-core/types'
import { Button } from '@kutup/ui/components/button'
import { refreshChat, useChat } from '../../app/chatStore'
import { Avatar } from '../../components/Avatar'
import { chatErrorMessage } from '../../lib/errors'
import { personName } from '../../lib/names'
import { groupIdOf } from '../../state/views'
import { Section } from '../details/DetailsPanel'
import { GroupLinkDialog } from './GroupLinkDialog'

/**
 * The group link in a group's details: its state and dialog, and, for
 * administrators, the people asking to join.
 */
export function GroupLinkSection({ group, canManage }: { group: LocalMlsConversationRecord; canManage: boolean }) {
  const { t } = useTranslation()
  const { service, snapshot, self } = useChat()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState<string | null>(null)
  const groupId = groupIdOf(group)
  const link = group.currentGroupInfo?.inviteLink
  const requests = snapshot.joinRequests.filter((request) => request.conversationId === groupId)
  const profiles = new Map(snapshot.profiles.map((p) => [p.peer, p]))

  useEffect(() => {
    if (canManage && link) void service?.refreshGroupJoinRequests().catch(() => undefined)
  }, [service, canManage, link])

  if (!canManage && !link) return null

  async function decide(requester: string, approve: boolean) {
    if (!service || busy) return
    setBusy(requester)
    try {
      await service.decideGroupJoinRequest(groupId, requester, approve)
      await refreshChat()
      toast.success(approve ? t('chat.groupLink.requestApproved') : t('chat.groupLink.requestDenied'))
    } catch (error) {
      toast.error(chatErrorMessage(error, t))
    } finally {
      setBusy(null)
    }
  }

  return (
    <Section title={t('chat.groupLink.title')} testId="chat-group-link-section">
      <Button variant="outline" className="w-full justify-start" onClick={() => setOpen(true)} data-testid="chat-group-link-open">
        <Link2 />
        <span className="flex-1 text-left">{t('chat.groupLink.title')}</span>
        <span className="text-xs text-muted-foreground">
          {link
            ? link.approvalRequired ? t('chat.groupLink.stateApproval') : t('chat.groupLink.stateOn')
            : t('chat.groupLink.stateOff')}
        </span>
      </Button>
      {canManage && requests.length > 0 ? (
        <div className="mt-4" data-testid="chat-group-join-requests">
          <p className="mb-2 text-sm font-medium">{t('chat.groupLink.requestsTitle', { count: requests.length })}</p>
          <ul className="space-y-1">
            {requests.map((request) => {
              const name = personName(request.requester, profiles, self!.address, t)
              return (
                <li key={request.requester} className="flex items-center gap-3 rounded-lg px-2 py-1.5">
                  <Avatar name={name} size={32} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm">{name}</span>
                    <span className="block truncate text-xs text-muted-foreground">{request.requester}</span>
                  </span>
                  <Button size="sm" variant="ghost" disabled={busy !== null} onClick={() => void decide(request.requester, false)} data-testid="chat-join-request-deny">
                    {t('chat.groupLink.deny')}
                  </Button>
                  <Button size="sm" disabled={busy !== null} onClick={() => void decide(request.requester, true)} data-testid="chat-join-request-approve">
                    {t('chat.groupLink.approve')}
                  </Button>
                </li>
              )
            })}
          </ul>
        </div>
      ) : null}
      <GroupLinkDialog group={group} canManage={canManage} open={open} onOpenChange={setOpen} />
    </Section>
  )
}
