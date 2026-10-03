import { canonicalAccountAddress } from './identity'
import type {
  LocalMlsConversationRecord,
  MlsInvitationFeedback,
} from './types'

export interface MlsGroupInvitationReadiness {
  pending: string[]
  refused: string[]
  blocksSending: boolean
}

/**
 * Every roster addition is bound to its exact client-private join epoch.
 * Acceptance may arrive either through the origin-scoped server receipt or
 * the MLS-encrypted group control; an old receipt cannot authorize a re-add.
 * Non-administrators do not derive send authorization from readiness state.
 */
export function mlsGroupInvitationReadiness(
  group: LocalMlsConversationRecord,
  feedback: MlsInvitationFeedback[],
  selfAddress: string | null,
): MlsGroupInvitationReadiness {
  const self = group.currentRoster.find(
    member => canonicalAccountAddress(member.address) === selfAddress,
  )
  if (!self?.isAdmin) return { pending: [], refused: [], blocksSending: false }

  const decisions = new Map<string, MlsInvitationFeedback>()
  for (const entry of feedback) {
    if (
      entry.conversationId !== group.request.genesis.conversationId
      || entry.incarnation !== group.request.genesis.incarnation
    ) continue
    const address = canonicalAccountAddress(entry.member)
    const previous = decisions.get(address)
    if (!previous || entry.invitedEpoch > previous.invitedEpoch) {
      decisions.set(address, entry)
    }
  }

  const pending: string[] = []
  const refused: string[] = []
  for (const member of group.currentRoster) {
    const address = canonicalAccountAddress(member.address)
    if (address === selfAddress) continue
    const joinedEpoch = group.memberJoinedEpochs.get(address)
    if (
      typeof joinedEpoch === 'number'
      && Number.isSafeInteger(joinedEpoch)
      && joinedEpoch >= 0
      && group.acceptedInvitationEpochs.get(address) === joinedEpoch
    ) {
      continue
    }
    const feedbackEntry = decisions.get(address)
    const decision = feedbackEntry && feedbackEntry.invitedEpoch === joinedEpoch
      ? feedbackEntry.decision
      : undefined
    if (decision === 'accepted') continue
    if (decision === 'rejected' || decision === 'expired') refused.push(address)
    else pending.push(address)
  }
  pending.sort()
  refused.sort()
  return {
    pending,
    refused,
    blocksSending: pending.length > 0 || refused.length > 0,
  }
}
