import { describe, expect, it } from 'vitest'
import { mlsGroupInvitationReadiness } from './group-readiness'
import type {
  LocalMlsConversationRecord,
  MlsInvitationFeedback,
} from './types'

const conversationId = '4cc2114c-8015-4e78-9af8-2f5f71c18cf1'
const alice = { username: 'alice', server: 'a.test' }
const bob = { username: 'bob', server: 'b.test' }

function group(isAdmin = true): LocalMlsConversationRecord {
  return {
    request: {
      genesis: {
        conversationId,
        incarnation: 1,
      },
      members: [{ address: alice, isAdmin: true }],
    },
    currentRoster: [
      { address: alice, isAdmin },
      { address: bob, isAdmin: false },
    ],
    memberJoinedEpochs: new Map([
      ['alice@a.test', 0],
      ['bob@b.test', 1],
    ]),
    acceptedInvitationEpochs: new Map([['alice@a.test', 0]]),
  } as unknown as LocalMlsConversationRecord
}

function feedback(decision: MlsInvitationFeedback['decision']): MlsInvitationFeedback {
  return {
    protocolVersion: 1,
    conversationId,
    incarnation: 1,
    member: bob,
    invitedEpoch: 1,
    decision,
    decidedAt: 1_785_249_600,
  }
}

describe('MLS group invitation readiness', () => {
  it('blocks an administrator until a later member accepts', () => {
    expect(mlsGroupInvitationReadiness(group(), [], 'alice@a.test')).toEqual({
      pending: ['bob@b.test'],
      refused: [],
      blocksSending: true,
    })
  })

  it('unblocks only an authenticated accepted receipt', () => {
    expect(
      mlsGroupInvitationReadiness(group(), [feedback('accepted')], 'alice@a.test'),
    ).toEqual({ pending: [], refused: [], blocksSending: false })
    expect(
      mlsGroupInvitationReadiness(group(), [feedback('rejected')], 'alice@a.test'),
    ).toEqual({
      pending: [],
      refused: ['bob@b.test'],
      blocksSending: true,
    })
  })

  it('accepts the MLS-encrypted receipt and rejects an old re-add receipt', () => {
    const accepted = group()
    accepted.acceptedInvitationEpochs.set('bob@b.test', 1)
    expect(mlsGroupInvitationReadiness(accepted, [], 'alice@a.test')).toEqual({
      pending: [],
      refused: [],
      blocksSending: false,
    })
    accepted.memberJoinedEpochs.set('bob@b.test', 3)
    expect(mlsGroupInvitationReadiness(accepted, [], 'alice@a.test')).toEqual({
      pending: ['bob@b.test'],
      refused: [],
      blocksSending: true,
    })
  })

  it('does not infer missing feedback for non-administrators', () => {
    expect(mlsGroupInvitationReadiness(group(false), [], 'alice@a.test')).toEqual({
      pending: [],
      refused: [],
      blocksSending: false,
    })
  })
})
