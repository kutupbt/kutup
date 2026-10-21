import { Loader2, Users } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import type { ChatGroupLinkPreview } from '@kutup/chat-core/types'
import { Avatar } from '@kutup/ui/components/avatar'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { refreshChat, useChat } from '../../app/chatStore'
import { chatErrorMessage } from '../../lib/errors'
import { closeJoinLink } from '../../lib/joinLink'
import { pathForConversation } from '../list/paths'

type Found = Extract<ChatGroupLinkPreview, { kind: 'group' }>

type View =
  | { kind: 'loading' }
  | { kind: 'failed'; message: string }
  | { kind: 'found'; preview: Found }

/**
 * A pairwise group's link (docs/plans/pairwise-groups.md §4): what the
 * group's members wrote about it, read under the link, then joining at once
 * or asking an administrator, who sees the request at their next sync.
 */
export function ChatGroupJoinDialog({ fragment }: { fragment: string }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { service } = useChat()
  const [view, setView] = useState<View>({ kind: 'loading' })
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!service) return
    let current = true
    service
      .previewChatGroupLink(fragment)
      .then((preview) => {
        if (!current) return
        if (preview.kind === 'group') setView({ kind: 'found', preview })
        else if (preview.kind === 'invalid') setView({ kind: 'failed', message: t('chat.chatGroupLink.invalid') })
        else setView({ kind: 'failed', message: t('chat.chatGroupLink.unreachable') })
      })
      .catch((error: unknown) => current && setView({ kind: 'failed', message: chatErrorMessage(error, t) }))
    return () => {
      current = false
    }
  }, [fragment, service, t])

  function openGroup(groupId: string) {
    closeJoinLink()
    void navigate(pathForConversation({ kind: 'group', groupId }))
  }

  async function join(preview: Found) {
    if (!service || busy) return
    setBusy(true)
    try {
      const joined = await service.joinChatGroupByLink(fragment)
      await refreshChat()
      if (joined.kind === 'joined') {
        toast.success(t('chat.chatGroupLink.joined'))
        openGroup(preview.groupId)
      } else if (joined.kind === 'requested') {
        closeJoinLink()
        toast.success(t('chat.chatGroupLink.requested'))
      } else if (joined.kind === 'invalid') {
        setView({ kind: 'failed', message: t('chat.chatGroupLink.invalid') })
      } else {
        toast.error(t('chat.chatGroupLink.unreachable'))
      }
    } catch (error) {
      toast.error(chatErrorMessage(error, t))
    } finally {
      setBusy(false)
    }
  }

  async function withdraw(preview: Found) {
    if (!service || busy) return
    setBusy(true)
    try {
      const outcome = await service.cancelChatGroupRequest(preview.groupId)
      await refreshChat()
      if (outcome.kind === 'joined') {
        toast.success(t('chat.chatGroupLink.joined'))
        openGroup(preview.groupId)
        return
      }
      closeJoinLink()
      if (outcome.kind === 'canceled') toast.success(t('chat.chatGroupLink.withdrawn'))
      else if (outcome.kind === 'denied') toast.message(t('chat.chatGroupLink.denied'))
      else toast.error(t('chat.chatGroupLink.unreachable'))
    } catch (error) {
      toast.error(chatErrorMessage(error, t))
    } finally {
      setBusy(false)
    }
  }

  const preview = view.kind === 'found' ? view.preview : null
  const title = preview?.title || t('chat.chatGroupLink.untitled')
  return (
    <Dialog open onOpenChange={(open) => !open && !busy && closeJoinLink()}>
      <DialogContent className="sm:max-w-sm" data-testid="chat-group-join-dialog">
        <DialogHeader>
          <DialogTitle>{t('chat.groupLink.joinTitle')}</DialogTitle>
          <DialogDescription>{t('chat.groupLink.joinDescription')}</DialogDescription>
        </DialogHeader>

        {view.kind === 'loading' ? (
          <p className="flex items-center justify-center gap-2 py-6 text-sm text-muted-foreground">
            <Loader2 className="size-4 animate-spin" aria-hidden />
            {t('chat.groupLink.looking')}
          </p>
        ) : null}

        {view.kind === 'failed' ? (
          <p className="py-4 text-sm" role="alert" data-testid="chat-group-join-failed">{view.message}</p>
        ) : null}

        {preview ? (
          <div className="flex flex-col items-center gap-2 py-2 text-center" data-testid="chat-group-join-preview">
            <Avatar name={title} image={preview.avatar?.data} contentType={preview.avatar?.contentType} group size={80} />
            <h3 className="mt-1 text-lg font-semibold" dir="auto">{title}</h3>
            <p className="flex items-center gap-1 text-sm text-muted-foreground">
              <Users className="size-4" aria-hidden />
              {t('chat.group.members', { count: preview.memberCount })}
            </p>
            {preview.description ? (
              <p className="max-w-full whitespace-pre-line break-words text-sm" dir="auto">{preview.description}</p>
            ) : null}
            {preview.status === 'member' ? (
              <p className="mt-2 text-sm text-muted-foreground">{t('chat.groupLink.alreadyMember')}</p>
            ) : preview.status === 'requesting' ? (
              <p className="mt-2 text-sm text-muted-foreground">{t('chat.chatGroupLink.requestPending')}</p>
            ) : preview.requiresApproval ? (
              <p className="mt-2 text-sm text-muted-foreground">{t('chat.chatGroupLink.approvalNeeded')}</p>
            ) : null}
          </div>
        ) : null}

        {preview ? (
          <DialogFooter>
            {preview.status === 'member' ? (
              <Button onClick={() => openGroup(preview.groupId)} data-testid="chat-group-join-open">
                {t('chat.groupLink.openGroup')}
              </Button>
            ) : preview.status === 'requesting' ? (
              <Button variant="outline" disabled={busy} onClick={() => void withdraw(preview)} data-testid="chat-group-join-withdraw">
                {t('chat.chatGroupLink.withdraw')}
              </Button>
            ) : (
              <Button disabled={busy} onClick={() => void join(preview)} data-testid="chat-group-join-submit">
                {busy ? <Loader2 className="animate-spin" /> : null}
                {preview.requiresApproval ? t('chat.groupLink.requestToJoin') : t('chat.groupLink.join')}
              </Button>
            )}
          </DialogFooter>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}
