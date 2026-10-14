import { describe, expect, it } from 'vitest'
import en from '@kutup/i18n/locales/en.json'
import tr from '@kutup/i18n/locales/tr.json'
import { describeHeadEvent } from './dataState'

const anchor = (sequence: number) => ({ sequence, digest: 'd' })
const interpolate = (messages: unknown) => (key: string, values?: Record<string, unknown>) => {
  const text = key.split('.').reduce<unknown>((node, part) => (node as Record<string, unknown>)[part], messages)
  if (typeof text !== 'string') throw new Error(`missing ${key}`)
  return text.replace(/\{\{(\w+)\}\}/g, (_, name: string) => String(values?.[name]))
}

describe('describeHeadEvent', () => {
  it('words every kind of event, in both languages', () => {
    const events = [
      { kind: 'startedFresh', anchor: anchor(3), atMs: 1 },
      { kind: 'forgotten', from: anchor(9), atMs: 2 },
      ...(['rollback', 'fork', 'tooOld'] as const).map((kind) => ({
        kind: 'reanchored' as const,
        record: { from: anchor(9), to: anchor(4), status: { kind }, atMs: 3 },
      })),
    ] as const
    for (const messages of [en, tr]) {
      const t = interpolate(messages) as never
      const lines = events.map((event) => describeHeadEvent(event, t).text)
      expect(lines[0]).toContain('#3')
      expect(lines[1]).toContain('#9')
      for (const line of lines.slice(2)) expect(line).toMatch(/#9 → #4/)
      expect(new Set(lines).size).toBe(lines.length)
    }
  })
})
