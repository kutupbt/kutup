import { describe, expect, it } from 'vitest'
import { exactBytes } from './bytes'

describe('exactBytes', () => {
  it('copies only a view’s own bytes, never its backing buffer', () => {
    const memory = new Uint8Array([1, 2, 3, 4, 5, 6])
    const view = memory.subarray(2, 4)
    const bytes = exactBytes(view)
    expect(bytes.byteLength).toBe(2)
    expect([...new Uint8Array(bytes)]).toEqual([3, 4])
    // A copy: changing it leaves the original alone.
    new Uint8Array(bytes)[0] = 9
    expect(memory[2]).toBe(3)
    // A DataView's window, too.
    expect(exactBytes(new DataView(memory.buffer, 1, 3)).byteLength).toBe(3)
  })
})
