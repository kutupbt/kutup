import { describe, expect, it } from 'vitest'
import { clusterPoints, type Viewport } from './cluster'

const istanbul = { lat: 41.0082, lon: 28.9784 }
const view = (over: Partial<Viewport> = {}): Viewport => ({
  west: 28.9,
  south: 40.95,
  east: 29.06,
  north: 41.06,
  zoom: 12,
  width: 800,
  height: 600,
  ...over,
})

describe('clusterPoints', () => {
  it('groups points that would overlap, the first (newest) as the face', () => {
    const points = [
      { id: 'newest', ...istanbul },
      { id: 'near', lat: istanbul.lat + 0.001, lon: istanbul.lon + 0.001 },
      { id: 'apart', lat: 41.05, lon: 29.03 },
    ]
    const { clusters, visible } = clusterPoints(points, view())
    expect(visible).toEqual(['newest', 'near', 'apart'])
    expect(clusters.map((c) => [c.id, c.count])).toEqual([
      ['newest', 2],
      ['apart', 1],
    ])
    expect(clusters[0].bounds.north).toBeCloseTo(istanbul.lat + 0.001)
  })

  it('splits a group as the map zooms in', () => {
    const points = [
      { id: 'a', ...istanbul },
      { id: 'b', lat: istanbul.lat + 0.004, lon: istanbul.lon },
    ]
    expect(clusterPoints(points, view({ zoom: 12 })).clusters).toHaveLength(1)
    expect(clusterPoints(points, view({ zoom: 17, west: 28.97, east: 28.99, south: 41.0, north: 41.02 })).clusters).toHaveLength(2)
  })

  it('leaves out what is far off screen, groups what is just outside', () => {
    const points = [
      { id: 'in', ...istanbul },
      { id: 'edge', lat: 41.0082, lon: 29.0605 },
      { id: 'paris', lat: 48.8584, lon: 2.2945 },
    ]
    const { clusters, visible } = clusterPoints(points, view())
    expect(visible).toEqual(['in'])
    expect(clusters.map((c) => c.id).sort()).toEqual(['edge', 'in'])
  })

  it('works across the date line', () => {
    const points = [
      { id: 'fiji', lat: -17.7, lon: 179.9 },
      { id: 'samoa', lat: -17.7, lon: -179.9 },
    ]
    const across = { west: 179, east: -179, south: -18.5, north: -17, zoom: 5, width: 800, height: 600 }
    const { clusters, visible } = clusterPoints(points, across)
    expect(visible).toEqual(['fiji', 'samoa'])
    expect(clusters).toHaveLength(1)
    expect(clusters[0].count).toBe(2)
  })
})
