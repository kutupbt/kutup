import { describe, expect, it } from 'vitest'
import { formatCoordinates, openInMapsUrl } from './places'

const pier = { lat: 40.99, lon: 29.0234, label: 'Kadıköy pier' }

describe('places', () => {
  it('formats coordinates to about a metre', () => {
    expect(formatCoordinates({ lat: 41.0082, lon: -28.97841234 })).toBe('41.00820, -28.97841')
  })

  it('opens the right maps app', () => {
    expect(openInMapsUrl(pier, 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)')).toBe(
      'https://maps.apple.com/?ll=40.99,29.0234&q=Kad%C4%B1k%C3%B6y%20pier',
    )
    expect(openInMapsUrl(pier, 'Mozilla/5.0 (Linux; Android 14)')).toBe(
      'geo:40.99,29.0234?q=40.99,29.0234(Kad%C4%B1k%C3%B6y%20pier)',
    )
    expect(openInMapsUrl({ lat: 1, lon: 2 }, 'Mozilla/5.0 (X11; Linux x86_64)')).toBe(
      'https://www.openstreetmap.org/?mlat=1&mlon=2#map=16/1/2',
    )
  })
})
