import { Loader2, Users } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import type { InviteLinkLookup } from '@kutup/chat-core/invite-links'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { refreshChat, useChat } from '../../app/chatStore'
import { Avatar } from '@kutup/ui/components/avatar'
import { chatErrorMessage } from '../../lib/errors'
import { closeJoinLink, openJoinLink, useJoinLink } from '../../lib/joinLink'
import { pathForConversation } from '../list/paths'

type View =
  | { kind: 'paste' }
  | { kind: 'loading' }
  | { kind: 'failed'; message: string }
  | { kind: 'found'; lookup: InviteLinkLookup }
  | { kind: 'joining'; lookup: InviteLinkLookup }

/** How long to wait for an administrator's device to add this account. */
const JOIN_WAIT_MS = 90_000

/**
 * What a group link leads to, and asking to join: at once when the group
 * lets anyone with the link in, otherwise once an administrator approves.
 */
export function JoinGroupHost() {
  const url = useJoinLink()
  return url === null ? null : <JoinGroupDialog key={url} url={url} />
}

function JoinGroupDialog({ url }: { url: string }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { service, snapshot } = useChat()
  const [view, setView] = useState<View>(url ? { kind: 'loading' } : { kind: 'paste' })
  const [pasted, setPasted] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!url || !service) return
    let cancelled = false
    service
      .lookUpInviteLink(url)
      .then((lookup) => !cancelled && setView({ kind: 'found', lookup }))
      .catch((error: unknown) => !cancelled && setView({ kind: 'failed', message: chatErrorMessage(error, t) }))
    return () => {
      cancelled = true
    }
  }, [url, service, t])

  // Joined: the group arrived through the invitation the request led to.
  const joiningId = view.kind === 'joining' ? view.lookup.preview.conversationId : null
  const joined = joiningId !== null && snapshot.groups.some(
    (group) => group.request.genesis.conversationId === joiningId && group.status === 'active',
  )
  useEffect(() => {
    if (!joined || !joiningId) return
    closeJoinLink()
    toast.success(t('chat.groupLink.joined'))
    void navigate(pathForConversation({ kind: 'group', groupId: joiningId }))
  }, [joined, joiningId, navigate, t])
  useEffect(() => {
    if (view.kind !== 'joining') return
    const timer = setTimeout(() => {
      closeJoinLink()
      toast.info(t('chat.groupLink.joinLater'))
    }, JOIN_WAIT_MS)
    return () => clearTimeout(timer)
  }, [view.kind, t])

  function openGroup(conversationId: string) {
    closeJoinLink()
    void navigate(pathForConversation({ kind: 'group', groupId: conversationId }))
  }

  async function request(lookup: InviteLinkLookup) {
    if (!service || busy) return
    setBusy(true)
    try {
      if (lookup.request) await service.cancelJoinRequest(lookup.linkId)
      await service.requestToJoin(lookup)
      await refreshChat()
      if (lookup.preview.approvalRequired) {
        closeJoinLink()
        toast.success(t('chat.groupLink.requestSent'))
      } else {
        setView({ kind: 'joining', lookup })
      }
    } catch (error) {
      toast.error(chatErrorMessage(error, t))
    } finally {
      setBusy(false)
    }
  }

  async function cancel(lookup: InviteLinkLookup) {
    if (!service || busy) return
    setBusy(true)
    try {
      await service.cancelJoinRequest(lookup.linkId)
      await refreshChat()
      closeJoinLink()
      toast.success(t('chat.groupLink.requestCancelled'))
    } catch (error) {
      toast.error(chatErrorMessage(error, t))
    } finally {
      setBusy(false)
    }
  }

  function submitPasted(event: FormEvent) {
    event.preventDefault()
    if (pasted.trim()) openJoinLink(pasted.trim())
  }

  const lookup = view.kind === 'found' || view.kind === 'joining' ? view.lookup : null
  const preview = lookup?.preview
  const own = lookup?.request

  return (
    <Dialog open onOpenChange={(open) => !open && closeJoinLink()}>
      <DialogContent className="sm:max-w-sm" data-testid="chat-join-dialog">
        <DialogHeader>
          <DialogTitle>{t('chat.groupLink.joinTitle')}</DialogTitle>
          <DialogDescription>{view.kind === 'paste' ? t('chat.groupLink.pasteHint') : t('chat.groupLink.joinDescription')}</DialogDescription>
        </DialogHeader>

        {view.kind === 'paste' ? (
          <form onSubmit={submitPasted} className="space-y-3">
            <Field label={t('chat.groupLink.pasteLabel')}>
              {(props) => (
                <Input
                  {...props}
                  value={pasted}
                  onChange={(e) => setPasted(e.target.value)}
                  placeholder="https://…/join#…"
                  autoCapitalize="none"
                  autoCorrect="off"
                  autoFocus
                  data-testid="chat-join-paste"
                />
              )}
            </Field>
            <DialogFooter>
              <Button type="submit" disabled={!pasted.trim()}>{t('chat.groupLink.continue')}</Button>
            </DialogFooter>
          </form>
        ) : null}

        {view.kind === 'loading' ? (
          <p className="flex items-center justify-center gap-2 py-6 text-sm text-muted-foreground">
            <Loader2 className="size-4 animate-spin" aria-hidden />
            {t('chat.groupLink.looking')}
          </p>
        ) : null}

        {view.kind === 'failed' ? (
          <p className="py-4 text-sm" role="alert" data-testid="chat-join-failed">{view.message}</p>
        ) : null}

        {lookup && preview ? (
          <div className="flex flex-col items-center gap-2 py-2 text-center" data-testid="chat-join-preview">
            <Avatar name={preview.name} image={preview.avatar?.data} contentType={preview.avatar?.contentType} group size={80} />
            <h3 className="mt-1 text-lg font-semibold">{preview.name}</h3>
            <p className="flex items-center gap-1 text-sm text-muted-foreground">
              <Users className="size-4" aria-hidden />
              {t('chat.group.members', { count: preview.memberCount })}
            </p>
            {preview.description ? (
              <p className="max-w-full whitespace-pre-line break-words text-sm">{preview.description}</p>
            ) : null}
            {view.kind === 'joining' ? (
              <p className="mt-2 flex items-center gap-2 text-sm text-muted-foreground" data-testid="chat-join-waiting">
                <Loader2 className="size-4 animate-spin" aria-hidden />
                {t('chat.groupLink.joining')}
              </p>
            ) : lookup.member ? (
              <p className="mt-2 text-sm text-muted-foreground">{t('chat.groupLink.alreadyMember')}</p>
            ) : own?.status === 'pending' ? (
              <p className="mt-2 text-sm text-muted-foreground">{t('chat.groupLink.requestPending')}</p>
            ) : own?.status === 'denied' ? (
              <p className="mt-2 text-sm text-muted-foreground">{t('chat.groupLink.requestWasDenied')}</p>
            ) : preview.approvalRequired ? (
              <p className="mt-2 text-sm text-muted-foreground">{t('chat.groupLink.approvalNeeded')}</p>
            ) : null}
          </div>
        ) : null}

        {view.kind === 'found' && lookup && preview ? (
          <DialogFooter>
            {lookup.member ? (
              <Button onClick={() => openGroup(preview.conversationId)} data-testid="chat-join-open">
                {t('chat.groupLink.openGroup')}
              </Button>
            ) : own?.status === 'pending' ? (
              <Button variant="outline" disabled={busy} onClick={() => void cancel(lookup)} data-testid="chat-join-cancel">
                {t('chat.groupLink.cancelRequest')}
              </Button>
            ) : (
              <Button disabled={busy} onClick={() => void request(lookup)} data-testid="chat-join-submit">
                {busy ? <Loader2 className="animate-spin" /> : null}
                {preview.approvalRequired ? t('chat.groupLink.requestToJoin') : t('chat.groupLink.join')}
              </Button>
            )}
          </DialogFooter>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}
