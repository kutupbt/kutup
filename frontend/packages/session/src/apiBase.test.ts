import { describe, expect, it } from 'vitest'
import { apiBase, resolveApiBase } from './apiBase'

describe('apiBase', () => {
  it('is same-origin /api/v1', async () => {
    expect(await resolveApiBase()).toBe('/api/v1')
    expect(apiBase()).toBe('/api/v1')
  })
})
