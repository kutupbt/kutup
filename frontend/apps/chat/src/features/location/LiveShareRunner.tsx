import { useEffect } from 'react'
import type { ConversationId } from '@kutup/chat-core/types'
import { useChat } from '../../app/chatStore'
import { liveShares } from './liveShares'

/**
 * Connects this tab's live-location shares to the open chat: how to send
 * the share messages and this account's server. Pairwise groups take text
 * only for now, so no share runs in a group: one left from before ends at
 * its next update, with nobody to hand a key to. A share this account
 * stopped from another device ends here too.
 */
export function LiveShareRunner() {
  const { service, capabilities, snapshot, self } = useChat()

  useEffect(() => {
    const server = capabilities?.serverName
    const address = self?.key
    if (!service || !server || !address) return
    liveShares.attach({
      sender: service,
      server,
      self: address,
      rosterOf: (conversation: ConversationId) => (conversation.kind === 'group' ? [] : null),
    })
    return () => liveShares.detach()
  }, [service, capabilities?.serverName, self?.key])

  useEffect(() => {
    for (const message of snapshot.history) {
      const stop = message.content.liveLocationStop
      if (stop && message.direction === 'outgoing' && liveShares.isSharing(stop.shareId)) void liveShares.ended(stop.shareId)
    }
  }, [snapshot.history])

  return null
}
