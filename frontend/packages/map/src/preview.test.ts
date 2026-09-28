import { describe, expect, it } from 'vitest'
import { creditText, previewBounds } from './preview'

describe('previewBounds', () => {
  it('is null for an empty list', () => {
    expect(previewBounds([])).toBeNull()
  })

  it('covers every place', () => {
    expect(
      previewBounds([
        { lat: 41.01, lon: 28.97 },
        { lat: 39.92, lon: 32.85 },
        { lat: 38.42, lon: 27.14 },
      ]),
    ).toEqual([27.14, 38.42, 32.85, 41.01])
  })

  it('is a point for one place', () => {
    expect(previewBounds([{ lat: 10, lon: 20 }])).toEqual([20, 10, 20, 10])
  })
})

describe('creditText', () => {
  it('turns the HTML attribution into one plain line', () => {
    expect(
      creditText(
        '<a href="https://openfreemap.org" target="_blank">OpenFreeMap</a> &copy; <a href="https://www.openmaptiles.org/">OpenMapTiles</a>\n Data from <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
      ),
    ).toBe('OpenFreeMap © OpenMapTiles Data from OpenStreetMap')
  })

  it('keeps no markup', () => {
    expect(creditText('<img src=x onerror=alert(1)>© Someone')).toBe('© Someone')
  })
})
