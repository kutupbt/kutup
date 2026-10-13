import { describe, expect, it } from 'vitest'
import { duplicateKey, duplicateKeys, filesOf, joinLivePhotos, type Photo } from './library'

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

describe('duplicates', () => {
  const sha = 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc='
  const stored = (id: string, name: string, sha256: string | null) =>
    ({ id, file: { name, sha256 }, media: null }) as unknown as Photo

  it('are found by name and the content SHA-256 in the file’s metadata', () => {
    const keys = duplicateKeys([stored('a', 'IMG_0001.JPG', sha), stored('b', 'IMG_0002.jpg', null)])
    // The same photo chosen again, whatever case or `(2)` its name has.
    expect(keys.get(duplicateKey('img_0001 (2).jpg', sha))).toBe('a')
    // Another photo under the same name is not one.
    expect(keys.get(duplicateKey('IMG_0001.JPG', 'AAAA' + sha.slice(4)))).toBeUndefined()
    // One without a recorded SHA-256 is never taken for a duplicate.
    expect(keys.size).toBe(1)
  })
})
