import { describe, expect, it } from 'vitest'
import { filesOf, joinLivePhotos, type Photo } from './library'

const photo = (id: string, kind: 'image' | 'video', liveOf?: string) =>
  ({ id, kind, takenAt: 0, dated: true, media: liveOf ? { liveOf } : null }) as unknown as Photo

describe('live photos in the library', () => {
  it('puts a video with its still and out of the list', () => {
    const joined = joinLivePhotos([photo('s', 'image'), photo('v', 'video', 's'), photo('x', 'video')])
    expect(joined.map((p) => p.id)).toEqual(['s', 'x'])
    expect(joined[0].live?.id).toBe('v')
    expect(filesOf(joined[0]).map((p) => p.id)).toEqual(['s', 'v'])
  })

  it('keeps a video whose still is not here', () => {
    expect(joinLivePhotos([photo('v', 'video', 'gone')]).map((p) => p.id)).toEqual(['v'])
  })
})
