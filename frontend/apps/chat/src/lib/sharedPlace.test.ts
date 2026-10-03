import { describe, expect, it } from 'vitest'
import { parseSharedPlace } from './sharedPlace'

describe('a place shared from Maps', () => {
  it('reads coordinates and a label from the fragment', () => {
    expect(parseSharedPlace('#lat=41.02&lon=28.97&label=Galata%20Tower')).toEqual({ lat: 41.02, lon: 28.97, label: 'Galata Tower' })
    expect(parseSharedPlace('#lat=0&lon=0')).toEqual({ lat: 0, lon: 0 })
  })

  it('refuses what is not a place', () => {
    expect(parseSharedPlace('')).toBeNull()
    expect(parseSharedPlace('#lat=91&lon=0')).toBeNull()
    expect(parseSharedPlace('#lat=x&lon=0')).toBeNull()
    expect(parseSharedPlace('#lon=10')).toBeNull()
  })

  it('shortens a long label', () => {
    expect(parseSharedPlace(`#lat=1&lon=1&label=${'a'.repeat(300)}`)?.label).toHaveLength(100)
  })
})
