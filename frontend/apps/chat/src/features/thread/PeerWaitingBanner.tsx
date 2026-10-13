import { Clock } from 'lucide-react'
import { useSyncExternalStore } from 'react'
import { useTranslation } from 'react-i18next'
import { useChatService } from '../../app/chatStore'

/**
 * Above a one-to-one conversation whose recipient's server does not support
 * this Chat version yet (docs/federation-protocol.md, `peerUnsupported`):
 * messages to them wait, in order, and go once that server upgrades. Said
 * here so a message that does not arrive is not a mystery.
 */
export function PeerWaitingBanner({ address }: { address: string }) {
  const { t } = useTranslation()
  const service = useChatService()
  const waiting = useSyncExternalStore(
    (onChange) => service.subscribeWaitingPeers(onChange),
    () => service.isPeerWaiting(address),
  )
  if (!waiting) return null
  const server = address.split('@')[1] ?? address
  return (
    <div
      className="flex items-center gap-2 border-b border-border bg-muted/50 px-4 py-1.5 text-sm"
      data-testid="chat-peer-waiting"
      role="status"
    >
      <Clock className="size-4 shrink-0 text-muted-foreground" aria-hidden />
      <span className="min-w-0 flex-1">{t('chat.peerWaiting', { server })}</span>
    </div>
  )
}
