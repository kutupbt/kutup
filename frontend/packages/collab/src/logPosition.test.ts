import { describe, expect, it } from 'vitest'
import { LogPosition } from './logPosition'

describe('LogPosition', () => {
  it('advances over a gap only once it closes', () => {
    const position = new LogPosition()
    position.loaded(4)
    position.stored(6)
    expect(position.applied).toBe(4)
    position.stored(5)
    expect(position.applied).toBe(6)
    position.replayed(9)
    expect(position.applied).toBe(9)
  })

  it('never moves past a frame held back as unverified, so no save trims it', () => {
    const position = new LogPosition()
    position.loaded(10)
    position.stored(11)
    // The frame at 12 can't be checked now.
    position.hold()
    position.stored(12)
    position.stored(13)
    position.replayed(40, 50)
    // Saves record this, and the server trims only up to it: 12 stays.
    expect(position.applied).toBe(11)
    // The next connection resumes from 11 and checks 12 again.
    position.connected()
    expect(position.held).toBe(false)
    position.stored(12)
    expect(position.applied).toBe(12)
  })
})
