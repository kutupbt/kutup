import { describe, expect, it } from 'vitest'
import { effectiveMap, usesRelay, type MapConfig } from './config'

const base: MapConfig = {
  enabled: true,
  proxy: 'available',
  providers: [
    {
      id: 'openfreemap',
      name: 'OpenFreeMap',
      kind: 'vector',
      url: 'https://tiles.openfreemap.org/styles/liberty',
      proxyUrl: '/api/maps/proxy/openfreemap/styles/liberty',
      attribution: 'OpenFreeMap',
    },
    {
      id: 'openstreetmap',
      name: 'OpenStreetMap',
      kind: 'raster',
      url: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
      proxyUrl: '/api/maps/proxy/openstreetmap/{z}/{x}/{y}.png',
      attribution: '© OpenStreetMap contributors',
    },
  ],
  preferences: { enabled: true, provider: 'openstreetmap', viaProxy: true },
}

describe('effectiveMap', () => {
  it('is nothing until the person turns maps on, or when the administrator turned them off', () => {
    expect(effectiveMap({ ...base, preferences: { ...base.preferences, enabled: false } }, 'https://x')).toBeNull()
    expect(effectiveMap({ ...base, enabled: false }, 'https://x')).toBeNull()
    expect(effectiveMap(undefined, 'https://x')).toBeNull()
  })

  it('uses the chosen provider through the relay', () => {
    const map = effectiveMap(base, 'https://drive.example.org')!
    expect(map.provider.id).toBe('openstreetmap')
    expect(map.viaProxy).toBe(true)
    expect(map.url).toBe('https://drive.example.org/api/maps/proxy/openstreetmap/{z}/{x}/{y}.png')
  })

  it('goes direct when the person chose so, unless the relay is enforced', () => {
    const direct = { ...base, preferences: { ...base.preferences, viaProxy: false } }
    expect(effectiveMap(direct, 'https://x')!.url).toBe('https://tile.openstreetmap.org/{z}/{x}/{y}.png')
    expect(effectiveMap({ ...direct, proxy: 'enforced' }, 'https://x')!.viaProxy).toBe(true)
  })

  it('falls back to the first provider when the chosen one is no longer offered', () => {
    const map = effectiveMap({ ...base, preferences: { ...base.preferences, provider: 'custom' } }, 'https://x')!
    expect(map.provider.id).toBe('openfreemap')
  })

  it('reads the relay mode', () => {
    expect(usesRelay('off', true)).toBe(false)
    expect(usesRelay('available', false)).toBe(false)
    expect(usesRelay('enforced', false)).toBe(true)
  })
})
