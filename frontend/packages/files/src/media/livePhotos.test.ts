import { describe, expect, it } from 'vitest'
import { looksLive, pairLivePhotos } from './livePhotos'

const f = (name: string) => ({ name })

describe('live photos', () => {
  it('pairs a still and a video with one name', () => {
    const still = f('IMG_1234.HEIC')
    const video = f('IMG_1234.MOV')
    const other = f('IMG_9999.JPG')
    const pairs = pairLivePhotos([still, video, other])
    expect(pairs.get(video)).toBe(still)
    expect(pairs.size).toBe(1)
  })

  it("follows exports' suffixes and ignores case", () => {
    const still = f('photo.jpg')
    const video = f('PHOTO_HEVC.mp4')
    expect(pairLivePhotos([still, video]).get(video)).toBe(still)
  })

  it('pairs nothing when a name is not one still and one video', () => {
    expect(pairLivePhotos([f('a.jpg'), f('a.heic'), f('a.mov')]).size).toBe(0)
    expect(pairLivePhotos([f('a.png'), f('a.mov')]).size).toBe(0)
    expect(pairLivePhotos([f('a.mov')]).size).toBe(0)
  })

  it('needs a short video taken near the still', () => {
    expect(looksLive({ takenAt: 0 }, { takenAt: 1000, durationMs: 2900 })).toBe(true)
    expect(looksLive(undefined, undefined)).toBe(true)
    expect(looksLive({ takenAt: 0 }, { durationMs: 60_000 })).toBe(false)
    expect(looksLive({ takenAt: 0 }, { takenAt: 3 * 24 * 3600 * 1000 })).toBe(false)
  })
})
