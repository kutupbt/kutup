import { describe, expect, it } from 'vitest'
import { apiBase, resolveApiBase } from './apiBase'

describe('apiBase', () => {
  it('is same-origin /api', async () => {
    expect(await resolveApiBase()).toBe('/api')
    expect(apiBase()).toBe('/api')
  })
})
