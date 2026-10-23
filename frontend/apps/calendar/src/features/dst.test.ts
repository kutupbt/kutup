// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from 'vitest'

// The real conversions: the Rust crate's, through its browser build.
vi.mock('@kutup/crypto/rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([import('node:fs/promises'), import('../../../../wasm/crypto-calendar-wasm/kutup_crypto_wasm.js')])
  const wasm = await readFile(new URL('../../../../wasm/crypto-calendar-wasm/kutup_crypto_wasm_bg.wasm', import.meta.url))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: () => Promise.resolve(module) }
})
const opened = vi.fn()
vi.mock('./editorState', () => ({
  openEditor: (target: unknown) => {
    opened(target)
  },
}))

const { openMoved, openNew } = await import('./moves')
type Placed = import('./placement').Placed

const BERLIN = 'Europe/Berlin'

/** A timed event in Berlin, shown in `view`. */
function berlinEvent(start: string, end: string): Placed {
  return {
    event: { fields: { start: { zoned: { local: start, tzid: BERLIN } } } } as unknown as Placed['event'],
    color: '#000',
    allDay: false,
    start,
    end,
    firstDay: start.slice(0, 10),
    afterLastDay: end.slice(0, 10),
  }
}

beforeEach(() => opened.mockReset())

describe('the grid across Berlin’s changes of offset (2026)', () => {
  it('moves an event into summer time at the same clock times (29 March)', async () => {
    await openMoved(berlinEvent('2026-03-28T09:00:00', '2026-03-28T10:00:00'), 1, 0, BERLIN)
    expect(opened).toHaveBeenCalledWith(expect.objectContaining({ moved: { start: '2026-03-29T09:00:00', end: '2026-03-29T10:00:00' } }))
  })

  it('keeps the wall-clock length across the night the clocks go back (25 October)', async () => {
    // 01:30–03:30 on the 25th lasts three real hours (02:00–03:00 twice);
    // moved there from the 24th it keeps its clock times.
    await openMoved(berlinEvent('2026-10-24T01:30:00', '2026-10-24T03:30:00'), 1, 0, BERLIN)
    expect(opened).toHaveBeenCalledWith(expect.objectContaining({ moved: { start: '2026-10-25T01:30:00', end: '2026-10-25T03:30:00' } }))
  })

  it('creates an event in the hour summer time skips an hour later, keeping its length', async () => {
    // 02:30 on 29 March doesn't exist: RFC 5545 reads it with the winter
    // offset, 03:30 summer time.
    await openNew('2026-03-29', 150, 180, BERLIN)
    expect(opened).toHaveBeenCalledWith({ kind: 'new', date: '2026-03-29', minutes: 210, endMinutes: 240 })
  })

  it('creates an event at a time that exists as it is, twice-happening ones included', async () => {
    await openNew('2026-03-29', 60, 90, BERLIN)
    expect(opened).toHaveBeenLastCalledWith({ kind: 'new', date: '2026-03-29', minutes: 60, endMinutes: 90 })
    await openNew('2026-10-25', 150, 180, BERLIN)
    expect(opened).toHaveBeenLastCalledWith({ kind: 'new', date: '2026-10-25', minutes: 150, endMinutes: 180 })
  })
})
