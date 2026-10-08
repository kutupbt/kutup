import { describe, expect, it } from 'vitest'
import type { ChatHistoryEntry } from './types'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { foldSearchText, searchChatHistory, searchWords, type ChatSearchMutationState } from './search'

const vectors = JSON.parse(readFileSync(resolve(__dirname, '../../../../crates/kutup-chat-core/tests/vectors/search_fold.json'), 'utf8')) as {
  cases: { input: string; folded: string; words: string[] }[]
}

function entry(
  id: string,
  timestampMs: number,
  content: ChatHistoryEntry['content'],
): ChatHistoryEntry {
  return {
    id,
    conversation: { kind: 'direct', address: { username: 'bob', server: 'b.test' } },
    peer: 'bob@b.test',
    direction: 'incoming',
    senderDeviceId: 1,
    timestampMs,
    delivered: true,
    deduplicated: false,
    content,
  }
}

const noMutations = new Map<string, ChatSearchMutationState>()

describe('private local Chat search', () => {
  it('matches every normalized term and returns newest results first', () => {
    const history = [
      entry('old', 1, {
        version: 1,
        kind: 'text',
        sentAt: 't',
        seq: '1',
        body: { text: 'Secure local search' },
        text: 'Secure local search',
      }),
      entry('new', 2, {
        version: 1,
        kind: 'text',
        sentAt: 't',
        seq: '2',
        body: { text: 'LOCAL and secure' },
        text: 'LOCAL and secure',
      }),
    ]

    expect(searchChatHistory(history, ' secure   LOCAL ', noMutations)
      .map(result => result.message.id)).toEqual(['new', 'old'])
  })

  it('uses the authoritative edit and never indexes deleted plaintext', () => {
    const edited = entry('edited', 1, {
      version: 1,
      kind: 'text',
      sentAt: 't',
      seq: '1',
      messageId: '11111111-1111-4111-8111-111111111111',
      body: { text: 'old secret' },
      text: 'old secret',
    })
    const deleted = entry('deleted', 2, {
      version: 1,
      kind: 'text',
      sentAt: 't',
      seq: '2',
      messageId: '22222222-2222-4222-8222-222222222222',
      body: { text: 'removed secret' },
      text: 'removed secret',
    })
    const mutations = new Map<string, ChatSearchMutationState>([
      ['11111111-1111-4111-8111-111111111111', { editedText: 'new wording', deleted: false }],
      ['22222222-2222-4222-8222-222222222222', { deleted: true }],
    ])

    expect(searchChatHistory([edited, deleted], 'secret', mutations)).toEqual([])
    expect(searchChatHistory([edited, deleted], 'wording', mutations)[0]?.preview)
      .toBe('new wording')
  })

  it('searches attachment filename and caption but excludes control-only content', () => {
    const attachment = entry('attachment', 1, {
      version: 1,
      kind: 'attachment',
      sentAt: 't',
      seq: '1',
      body: {},
      attachment: {
        version: 1,
        suite: 1,
        attachmentId: '11111111-1111-4111-8111-111111111111',
        originDomain: 'a.test',
        retrievalToken: 'token',
        ciphertextBytes: 1,
        ciphertextSha256: 'digest',
        attachmentKey: 'key',
        plaintextBytes: 1,
        filename: 'Quarterly Report.pdf',
        mimeType: 'application/pdf',
        mediaClass: 'file',
        caption: 'Board review',
      },
    })
    const control = entry('control', 2, {
      version: 1,
      kind: 'disappearingTimer',
      sentAt: 't',
      seq: '2',
      body: {},
      disappearingTimer: {},
    })

    expect(searchChatHistory([attachment, control], 'quarterly board', noMutations)
      .map(result => result.message.id)).toEqual(['attachment'])
  })

  it('bounds the local result set', () => {
    const history = Array.from({ length: 120 }, (_, index) => entry(`message-${index}`, index, {
      version: 1,
      kind: 'text',
      sentAt: 't',
      seq: String(index),
      body: { text: 'match' },
      text: 'match',
    }))

    expect(searchChatHistory(history, 'match', noMutations)).toHaveLength(100)
    expect(searchChatHistory(history, 'match', noMutations, 5)).toHaveLength(5)
  })

  it('folds exactly as the core index does (shared vectors)', () => {
    for (const { input, folded, words } of vectors.cases) {
      expect(foldSearchText(input), input).toBe(folded)
      expect(searchWords(input), input).toEqual(words)
    }
  })

  it('matches Turkish and accented words alike, at the start of a word only', () => {
    const history = [
      entry('city', 1, { version: 1, kind: 'text', sentAt: 't', seq: '1', body: {}, text: "İstanbul'da buluşalım" }),
      entry('call', 2, { version: 1, kind: 'text', sentAt: 't', seq: '2', body: {}, text: 'Çağrı geldi, KİTAPLAR hazır' }),
    ]
    const ids = (query: string) => searchChatHistory(history, query, noMutations).map(result => result.message.id)
    expect(ids('istanbul')).toEqual(['city'])
    expect(ids('ISTANBUL')).toEqual(['city'])
    expect(ids('ıstanbul')).toEqual(['city'])
    expect(ids('bulusalim')).toEqual(['city'])
    expect(ids('cagri kitap')).toEqual(['call'])
    expect(ids('tap')).toEqual([])
  })
})
