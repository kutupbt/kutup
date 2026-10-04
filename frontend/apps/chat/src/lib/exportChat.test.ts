import { describe, expect, it } from 'vitest'
import type { TFunction } from 'i18next'
import type { ChatHistoryEntry } from '@kutup/chat-core/types'
import type { MessageView } from '../state/views'
import { chatTranscript, transcriptFileName } from './exportChat'

const t = ((key: string, options?: Record<string, unknown>) =>
  options ? `${key}:${JSON.stringify(options)}` : key) as unknown as TFunction

function view(author: string, at: Date, text: string, extra: Partial<MessageView> = {}): MessageView {
  return {
    entry: { id: text, timestampMs: at.getTime(), content: { kind: 'text', text } } as unknown as ChatHistoryEntry,
    id: text,
    author,
    outgoing: author === 'me@a.test',
    mutation: null,
    replyTo: null,
    replyToMutation: null,
    reactions: [],
    receipt: null,
    timerChange: null,
    groupUpdate: null,
    callLog: null,
    undecryptable: null,
    groupCall: null,
    viewedOnce: null,
    poll: null,
    pollEnded: null,
    liveLocation: null,
    ...extra,
  }
}

describe('chatTranscript', () => {
  it('keeps a place\'s coordinates', () => {
    const at = new Date(2026, 8, 25, 14, 3)
    const place = view('bob@a.test', at, 'x', {
      entry: { id: 'p', timestampMs: at.getTime(), content: { kind: 'location', location: { lat: 40.9904, lon: 29.0231, label: 'Pier' } } } as unknown as ChatHistoryEntry,
    })
    const text = chatTranscript('Bob', [place], { self: 'me@a.test', nameOf: () => 'Bob', t, exportedAt: at })
    expect(text).toContain('Bob: chat.preview.location:{"label":"Pier"} (40.99040, 29.02310)')
  })

  it('writes one line per message with time and sender', () => {
    const at = new Date(2026, 8, 25, 14, 3)
    const text = chatTranscript('Bob', [
      view('bob@a.test', at, 'hello'),
      view('me@a.test', at, 'hi', { mutation: { editedText: 'hi!', deleted: false } }),
    ], { self: 'me@a.test', nameOf: (a) => (a === 'me@a.test' ? 'You' : 'Bob'), t, exportedAt: at })
    const lines = text.trim().split('\n')
    expect(lines[0]).toContain('chat.export.header')
    expect(lines[3]).toBe('[2026-09-25 14:03] Bob: hello')
    expect(lines[4]).toBe('[2026-09-25 14:03] You: hi! chat.export.edited')
  })

  it('names the file after the chat and the day', () => {
    expect(transcriptFileName('Ağaç / evi 🌲', new Date(2026, 0, 2))).toBe('kutup-Agac-evi-2026-01-02.txt')
  })
})
