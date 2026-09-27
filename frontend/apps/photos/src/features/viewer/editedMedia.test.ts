import { describe, expect, it } from 'vitest'
import { editedMedia } from './editedMedia'

const media = { takenAt: Date.UTC(2024, 6, 1, 16, 45), takenOffset: 180, takenFrom: 'exif' as const, lat: 41, lon: 29, hash: 'x' }
const form = { when: '2024-07-01T19:45', offset: 180, lat: '41', lon: '29', caption: '' }

describe('editing a photo', () => {
  it('keeps what was not changed', () => {
    expect(editedMedia(media, form, true, '2024-07-01T19:45', 180)).toEqual(media)
  })

  it('reads a new date as the clock where it was taken', () => {
    const next = editedMedia(media, { ...form, when: '2024-07-02T08:00', offset: 540 }, true, '2024-07-01T19:45', 180)
    expect(next).toMatchObject({ takenAt: Date.UTC(2024, 6, 1, 23, 0), takenOffset: 540, takenFrom: 'edited', hash: 'x' })
  })

  it('leaves an unknown date unknown unless it is set', () => {
    expect(editedMedia(null, { ...form, when: '2026-01-01T10:00', lat: '', lon: '', caption: 'Hi' }, false, '2026-01-01T10:00', undefined)).toEqual({ caption: 'Hi' })
  })

  it('removes the place and the caption when emptied, and refuses nonsense', () => {
    expect(editedMedia({ ...media, caption: 'old' }, { ...form, lat: '', lon: '', caption: ' ' }, true, form.when, 180)).toEqual({
      takenAt: media.takenAt,
      takenOffset: 180,
      takenFrom: 'exif',
      hash: 'x',
    })
    expect(editedMedia(media, { ...form, lat: '95' }, true, form.when, 180)).toBeNull()
    expect(editedMedia(media, { ...form, lat: '0', lon: '0' }, true, form.when, 180)).toBeNull()
  })
})
