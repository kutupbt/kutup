import { Ban, Clock, Lock, ShieldAlert } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { Button } from '@kutup/ui/components/button'
import { refreshChat, useChat } from '../../app/chatStore'
import { chatErrorMessage } from '../../lib/errors'
import type { ConversationModel } from './useConversationModel'

/**
 * What stands where the composer would when nothing can be written, as in
 * Signal: a message request's Accept / Reject / Block, a blocked contact's
 * Unblock, or why a group is read-only.
 */
export function ConversationBar({ model }: { model: ConversationModel }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { service } = useChat()
  const [busy, setBusy] = useState(false)
  const peer = model.address

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
      const Icon = model.readOnly === 'pendingInvitations' ? Clock : model.readOnly === 'adminsOnly' ? ShieldAlert : Lock
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
