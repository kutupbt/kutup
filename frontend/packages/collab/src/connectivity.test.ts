// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { collabSocketFailures, reportCollabSocket, resetCollabConnectivityForTesting, subscribeCollabConnectivity } from './connectivity'

describe('collab connectivity', () => {
  beforeEach(resetCollabConnectivityForTesting)

  it('counts attempts that never opened and forgets them when one does', () => {
    const changed = vi.fn()
    const stop = subscribeCollabConnectivity(changed)
    reportCollabSocket(false)
    reportCollabSocket(false)
    expect(collabSocketFailures()).toBe(2)
    reportCollabSocket(true)
    expect(collabSocketFailures()).toBe(0)
    // Already clear: nobody is told again.
    reportCollabSocket(true)
    expect(changed).toHaveBeenCalledTimes(3)
    stop()
    reportCollabSocket(false)
    expect(changed).toHaveBeenCalledTimes(3)
  })
})
