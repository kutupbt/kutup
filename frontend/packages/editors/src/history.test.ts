import { describe, expect, it } from 'vitest'
import type { VersionRow } from '@kutup/collab/api'
import { fileHistory, groupHistory, mayDeleteEntry, ORIGINAL, type HistoryEntry } from './history'

const ME = '11111111-1111-4111-8111-111111111111'
const OWNER = '22222222-2222-4222-8222-222222222222'

function row(id: string, createdAt: string, extra: Partial<VersionRow> = {}): VersionRow {
  return {
    id,
    storagePath: '',
    seqAtSnapshot: 0,
    docKeyId: 0,
    authorAccountId: ME,
    sizeBytes: 100,
    label: null,
    keepForever: false,
    createdAt,
    kind: 'file',
    keyGeneration: 1,
    revisionContentEnvelope: 'sealed',
    ...extra,
  }
}

function file(extra: Record<string, unknown> = {}) {
  return {
    name: 'photo.jpg',
    content: { revisionId: 'v2' } as never,
    stateRevisionId: null,
    originalRevisionId: 'r0',
    originalPruned: false,
    uploaderAccountId: OWNER,
    createdAt: '2026-11-01T10:00:00Z',
    originalKeyGeneration: 1,
    originalSizeBytes: 50,
    ...extra,
  }
}

describe('fileHistory', () => {
  it('lists whole-file versions and the original, newest first, current by what the metadata commits to', () => {
    const history = fileHistory(file(), [
      row('v2', '2026-11-03T10:00:00Z'),
      row('n1', '2026-11-02T12:00:00Z', { kind: 'yjs' }),
      row('v1', '2026-11-02T10:00:00Z'),
    ])
    expect(history.map((e) => e.id)).toEqual(['v2', 'v1', ORIGINAL])
    expect(history.filter((e) => e.current).map((e) => e.id)).toEqual(['v2'])
    const original = history[2]
    expect(original.authorAccountId).toBe(OWNER)
    expect(original.sizeBytes).toBe(50)
  })

  it('marks the original current while nothing replaced it, and leaves it out once pruned', () => {
    expect(fileHistory(file({ content: { revisionId: 'r0' } }), []).map((e) => [e.id, e.current])).toEqual([[ORIGINAL, true]])
    const pruned = fileHistory(file({ originalPruned: true }), [row('v2', '2026-11-03T10:00:00Z')])
    expect(pruned.map((e) => e.id)).toEqual(['v2'])
    expect(pruned[0].current).toBe(true)
  })

  it('lists a note’s saved states, the state its metadata names current', () => {
    const history = fileHistory(file({ name: 'notes.md', content: { revisionId: 'r0' }, stateRevisionId: 's1' }), [
      row('s2', '2026-11-03T10:00:00Z', { kind: 'yjs' }),
      row('s1', '2026-11-02T10:00:00Z', { kind: 'yjs' }),
    ])
    expect(history.map((e) => [e.id, e.current])).toEqual([
      ['s2', false],
      ['s1', true],
      [ORIGINAL, false],
    ])
  })

  it('reads a remote author from the server’s object form', () => {
    const [entry] = fileHistory(file({ originalPruned: true }), [
      row('v2', '2026-11-03T10:00:00Z', { remoteAuthor: { server: 'other.example', accountId: OWNER } as never }),
    ])
    expect(entry.remoteAuthor).toEqual({ server: 'other.example', accountId: OWNER })
  })
})

describe('mayDeleteEntry', () => {
  const history = fileHistory(file(), [row('v2', '2026-11-03T10:00:00Z'), row('v1', '2026-11-02T10:00:00Z', { authorAccountId: OWNER })])
  const byId = (id: string) => history.find((e) => e.id === id)!

  it('never the current version', () => {
    expect(mayDeleteEntry(byId('v2'), history, OWNER, OWNER)).toBe(false)
  })

  it('the owner any earlier one, an editor only their own', () => {
    expect(mayDeleteEntry(byId('v1'), history, OWNER, OWNER)).toBe(true)
    expect(mayDeleteEntry(byId('v1'), history, ME, OWNER)).toBe(false)
    expect(mayDeleteEntry(byId(ORIGINAL), history, OWNER, OWNER)).toBe(true)
    expect(mayDeleteEntry(byId(ORIGINAL), history, ME, OWNER)).toBe(false)
  })

  it('not a note’s original, which no whole-file version replaced', () => {
    const note = fileHistory(file({ name: 'a.md', stateRevisionId: 's1' }), [row('s1', '2026-11-03T10:00:00Z', { kind: 'yjs' })])
    expect(mayDeleteEntry(note.find((e) => e.id === ORIGINAL)!, note, OWNER, OWNER)).toBe(false)
  })
})

describe('groupHistory', () => {
  const at = (iso: string) => ({ id: iso, createdAt: iso }) as HistoryEntry

  it('groups as Proton: today, yesterday, weekdays, last week, months, years', () => {
    // Thursday 2026-11-19, local time.
    const now = new Date(2026, 10, 19, 15, 0)
    const local = (y: number, m: number, d: number) => new Date(y, m, d, 9, 0).toISOString()
    const groups = groupHistory(
      [
        at(local(2026, 10, 19)),
        at(local(2026, 10, 18)),
        at(local(2026, 10, 16)), // Monday this week
        at(local(2026, 10, 12)), // last week
        at(local(2026, 9, 3)),
        at(local(2026, 9, 1)),
        at(local(2025, 4, 1)),
      ],
      now,
    )
    expect(groups.map((g) => [g.kind, g.entries.length])).toEqual([
      ['today', 1],
      ['yesterday', 1],
      ['weekday', 1],
      ['lastWeek', 1],
      ['month', 2],
      ['year', 1],
    ])
  })
})
