import { beforeEach, describe, expect, it, vi } from 'vitest'
import { noteSessionVersion, resetSessionVersion, setSessionVersionHandler } from './sessionVersion'

describe('session version', () => {
  beforeEach(() => resetSessionVersion())

  it('runs the handler once when the version changes, not on the first one seen', async () => {
    const handler = vi.fn(() => Promise.resolve())
    setSessionVersionHandler(handler)
    noteSessionVersion('a1')
    noteSessionVersion('a1')
    expect(handler).not.toHaveBeenCalled()
    noteSessionVersion('b2')
    noteSessionVersion('b2')
    expect(handler).toHaveBeenCalledTimes(1)
    // Missing or empty headers change nothing.
    noteSessionVersion(undefined)
    noteSessionVersion('')
    expect(handler).toHaveBeenCalledTimes(1)
  })
})
