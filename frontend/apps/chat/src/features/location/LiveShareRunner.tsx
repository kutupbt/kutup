import { useEffect, useRef } from 'react'
import { canonicalAccountAddress } from '@kutup/chat-core/identity'
import type { ConversationId } from '@kutup/chat-core/types'
import { useChat } from '../../app/chatStore'
import { groupIdOf } from '../../state/views'
import { liveShares } from './liveShares'

/**
 * Connects this tab's live-location shares to the open chat: how to send
 * the share messages, this account's server, and each group's members now
 * (a share re-keys as soon as anyone leaves). A share this account stopped
 * from another device ends here too.
 */
export function LiveShareRunner() {
  const { service, capabilities, snapshot, self } = useChat()
  const groups = useRef(snapshot.groups)
  groups.current = snapshot.groups

  useEffect(() => {
    const server = capabilities?.serverName
    const address = self?.address
    if (!service || !server || !address) return
    liveShares.attach({
      sender: service,
      server,
      self: address,
      rosterOf: (conversation: ConversationId) => {
        if (conversation.kind !== 'group') return null
        const group = groups.current.find((g) => groupIdOf(g) === conversation.groupId)
        return group ? group.currentRoster.map((member) => canonicalAccountAddress(member.address)) : []
      },
    })
    return () => liveShares.detach()
  }, [service, capabilities?.serverName, self?.address])

  useEffect(() => {
    for (const message of snapshot.history) {
      const stop = message.content.liveLocationStop
      if (stop && message.direction === 'outgoing' && liveShares.isSharing(stop.shareId)) void liveShares.ended(stop.shareId)
    }
  }, [snapshot.history])

  return null
}
