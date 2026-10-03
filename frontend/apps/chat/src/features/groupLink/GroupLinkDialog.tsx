import { Copy, Loader2, RefreshCw, Share2 } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { InviteLinkChange } from '@kutup/chat-core/invite-links'
import type { LocalMlsConversationRecord } from '@kutup/chat-core/types'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { refreshChat, useChat } from '../../app/chatStore'
import { chatErrorMessage } from '../../lib/errors'
import { groupIdOf } from '../../state/views'

/**
 * A group's link: administrators turn it on or off, choose whether they
 * approve each request, and reset it; everyone in the group can share it
 * while it is on.
 */
export function GroupLinkDialog({
  group,
  canManage,
  open,
  onOpenChange,
}: {
  group: LocalMlsConversationRecord
  canManage: boolean
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { t } = useTranslation()
  const { service } = useChat()
  const [busy, setBusy] = useState(false)
  const [confirmReset, setConfirmReset] = useState(false)
  const groupId = groupIdOf(group)
  const info = group.currentGroupInfo
  const link = info?.inviteLink
  const url = link && service ? service.inviteLinkUrl(link) : null

  async function change(next: InviteLinkChange, done: string) {
    if (!service || busy) return
    setBusy(true)
    try {
      await service.changeInviteLink(groupId, next)
      await refreshChat()
      toast.success(done)
    } catch (error) {
      toast.error(chatErrorMessage(error, t))
    } finally {
      setBusy(false)
    }
  }

  async function copy() {
    if (!url) return
    try {
      await navigator.clipboard.writeText(url)
      toast.success(t('chat.groupLink.copied'))
    } catch {
      toast.error(t('chat.groupLink.copyFailed'))
    }
  }

  async function share() {
    if (!url || !info) return
    try {
      await navigator.share({ title: info.name, url })
    } catch (error) {
      if (!(error instanceof DOMException && error.name === 'AbortError')) void copy()
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md" data-testid="chat-group-link-dialog">
        <DialogHeader>
          <DialogTitle>{t('chat.groupLink.title')}</DialogTitle>
          <DialogDescription>{t('chat.groupLink.description')}</DialogDescription>
        </DialogHeader>

        {!info ? (
          <p className="text-sm text-muted-foreground">{t('chat.groupLink.nameFirst')}</p>
        ) : null}

        {info && canManage ? (
          <label className="flex items-start gap-3">
            <Checkbox
              checked={Boolean(link)}
              disabled={busy}
              onCheckedChange={(value) =>
                void change(
                  value === true ? { kind: 'enable', approvalRequired: true } : { kind: 'disable' },
                  value === true ? t('chat.groupLink.enabled') : t('chat.groupLink.disabled'),
                )}
              className="mt-0.5"
              data-testid="chat-group-link-toggle"
            />
            <span>
              <span className="block text-sm font-medium">{t('chat.groupLink.toggle')}</span>
              <span className="mt-1 block text-sm text-muted-foreground">{t('chat.groupLink.toggleHint')}</span>
            </span>
          </label>
        ) : null}

        {link && url ? (
          <div className="space-y-4">
            <div className="flex justify-center">
              <div className="rounded-xl border border-border bg-white p-3">
                <QRCodeSVG value={url} size={176} aria-label={t('chat.groupLink.qr')} />
              </div>
            </div>
            <code className="block break-all rounded-md bg-muted px-3 py-2 font-mono text-xs" data-testid="chat-group-link-url">
              {url}
            </code>
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" size="sm" onClick={() => void copy()} data-testid="chat-group-link-copy">
                <Copy />
                {t('chat.groupLink.copy')}
              </Button>
              {'share' in navigator ? (
                <Button variant="outline" size="sm" onClick={() => void share()}>
                  <Share2 />
                  {t('chat.groupLink.share')}
                </Button>
              ) : null}
              {canManage ? (
                <Button variant="outline" size="sm" disabled={busy} onClick={() => setConfirmReset(true)} data-testid="chat-group-link-reset">
                  <RefreshCw />
                  {t('chat.groupLink.reset')}
                </Button>
              ) : null}
            </div>
            {canManage ? (
              <label className="flex items-start gap-3">
                <Checkbox
                  checked={link.approvalRequired}
                  disabled={busy}
                  onCheckedChange={(value) =>
                    void change(
                      { kind: 'approval', approvalRequired: value === true },
                      value === true ? t('chat.groupLink.approvalOn') : t('chat.groupLink.approvalOff'),
                    )}
                  className="mt-0.5"
                  data-testid="chat-group-link-approval"
                />
                <span>
                  <span className="block text-sm font-medium">{t('chat.groupLink.approval')}</span>
                  <span className="mt-1 block text-sm text-muted-foreground">{t('chat.groupLink.approvalHint')}</span>
                </span>
              </label>
            ) : (
              <p className="text-sm text-muted-foreground">
                {link.approvalRequired ? t('chat.groupLink.approvalNeeded') : t('chat.groupLink.anyoneJoins')}
              </p>
            )}
          </div>
        ) : null}

        {busy ? (
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="size-4 animate-spin" aria-hidden />
            {t('chat.groupLink.working')}
          </p>
        ) : null}

        <ConfirmDestructive
          open={confirmReset}
          onOpenChange={setConfirmReset}
          title={t('chat.groupLink.resetTitle')}
          description={t('chat.groupLink.resetDescription')}
          submit={t('chat.groupLink.reset')}
          errorFallback={t('chat.errors.unavailable')}
          onConfirm={() => {
            setConfirmReset(false)
            void change({ kind: 'reset' }, t('chat.groupLink.wasReset'))
          }}
        />
      </DialogContent>
    </Dialog>
  )
}
