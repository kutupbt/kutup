import { describe, expect, it } from 'vitest'
import { i18n } from '@kutup/i18n'
import '../features/media/testI18n'
import type { ChatHistoryEntry } from '@kutup/chat-core/types'
import { threadView } from '../state/views'
import en from '../locales/en.json'
import tr from '../locales/tr.json'
import { renameText } from './renameText'

const t = i18n.t.bind(i18n)
const renamed = { from: 'ada_l@kutup.test', to: 'ada_lovelace@kutup.test', sequence: 1 }

describe('the rename line', () => {
  it('names the usernames, in English and Turkish', () => {
    expect(renameText(renamed, t)).toBe('ada_l changed their username to ada_lovelace')
    for (const line of [en.chat.renamed.line, tr.chat.renamed.line]) {
      expect(line).toContain('{{from}}')
      expect(line).toContain('{{to}}')
    }
  })

  it('shows in its thread as a notice of its own', () => {
    const entry = {
      id: 'rename:inc:1',
      conversation: { kind: 'direct', address: { username: 'ada_lovelace', server: 'kutup.test' } },
      sender: 'me@kutup.test',
      direction: 'outgoing',
      timestampMs: 1,
      delivered: true,
      deduplicated: false,
      content: { version: 1, kind: 'peerRenamed', sentAt: '', seq: '0', messageId: 'rename:inc:1', body: renamed, peerRenamed: renamed },
    } as unknown as ChatHistoryEntry
    const views = threadView([entry], 'direct:ada_lovelace@kutup.test', 'me@kutup.test', 2)
    expect(views).toHaveLength(1)
    expect(views[0].peerRenamed).toEqual(renamed)
  })
})
