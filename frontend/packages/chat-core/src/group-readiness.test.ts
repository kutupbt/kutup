import { describe, expect, it } from 'vitest'
import { mlsGroupInvitationReadiness } from './group-readiness'
import type {
  LocalMlsConversationRecord,
  MlsInvitationFeedback,
} from './types'

const conversationId = '4cc2114c-8015-4e78-9af8-2f5f71c18cf1'
const alice = { server: 'a.test', accountId: '00000000-0000-4000-8000-2bd806c97f0e' }
const bob = { server: 'b.test', accountId: '00000000-0000-4000-8000-81b637d8fcd2' }

function group(isAdmin = true): LocalMlsConversationRecord {
  return {
    request: {
      genesis: {
        conversationId,
        incarnation: 1,
      },
      members: [{ account: alice, isAdmin: true }],
    },
    currentRoster: [
      { account: alice, isAdmin },
      { account: bob, isAdmin: false },
    ],
    memberJoinedEpochs: new Map([
      ['aci:00000000-0000-4000-8000-2bd806c97f0e@a.test', 0],
      ['aci:00000000-0000-4000-8000-81b637d8fcd2@b.test', 1],
    ]),
    acceptedInvitationEpochs: new Map([['aci:00000000-0000-4000-8000-2bd806c97f0e@a.test', 0]]),
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
    expect(mlsGroupInvitationReadiness(group(), [], 'aci:00000000-0000-4000-8000-2bd806c97f0e@a.test')).toEqual({
      pending: ['aci:00000000-0000-4000-8000-81b637d8fcd2@b.test'],
      refused: [],
      blocksSending: true,
    })
  })

  it('unblocks only an authenticated accepted receipt', () => {
    expect(
      mlsGroupInvitationReadiness(group(), [feedback('accepted')], 'aci:00000000-0000-4000-8000-2bd806c97f0e@a.test'),
    ).toEqual({ pending: [], refused: [], blocksSending: false })
    expect(
      mlsGroupInvitationReadiness(group(), [feedback('rejected')], 'aci:00000000-0000-4000-8000-2bd806c97f0e@a.test'),
    ).toEqual({
      pending: [],
      refused: ['aci:00000000-0000-4000-8000-81b637d8fcd2@b.test'],
      blocksSending: true,
    })
  })

  it('accepts the MLS-encrypted receipt and rejects an old re-add receipt', () => {
    const accepted = group()
    accepted.acceptedInvitationEpochs.set('aci:00000000-0000-4000-8000-81b637d8fcd2@b.test', 1)
    expect(mlsGroupInvitationReadiness(accepted, [], 'aci:00000000-0000-4000-8000-2bd806c97f0e@a.test')).toEqual({
      pending: [],
      refused: [],
      blocksSending: false,
    })
    accepted.memberJoinedEpochs.set('aci:00000000-0000-4000-8000-81b637d8fcd2@b.test', 3)
    expect(mlsGroupInvitationReadiness(accepted, [], 'aci:00000000-0000-4000-8000-2bd806c97f0e@a.test')).toEqual({
      pending: ['aci:00000000-0000-4000-8000-81b637d8fcd2@b.test'],
      refused: [],
      blocksSending: true,
    })
  })

  it('does not infer missing feedback for non-administrators', () => {
    expect(mlsGroupInvitationReadiness(group(false), [], 'aci:00000000-0000-4000-8000-2bd806c97f0e@a.test')).toEqual({
      pending: [],
      refused: [],
      blocksSending: false,
    })
  })
})
