// @vitest-environment node
import { readFile } from 'node:fs/promises'
import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('@kutup/crypto/rustWasm', async () => {
  const module = await import('../../../../wasm/crypto-wasm/kutup_crypto_wasm.js')
  const wasm = await readFile(new URL('../../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm', import.meta.url))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: async () => module }
})

import { dateFromFileName, parseCameraDate } from './dates'
import { readImageFacts } from './exif'
import { mediaKindOf, readMedia } from './index'
import { parseIso6709, readVideoFacts } from './mp4'

async function fixture(name: string, type: string, lastModified = 0): Promise<File> {
  const bytes = await readFile(new URL(`./fixtures/${name}`, import.meta.url))
  return new File([bytes], name, { type, lastModified })
}

afterEach(() => {
  vi.useRealTimers()
})

describe('camera dates', () => {
  it('reads EXIF and ISO forms, with sub-seconds and time zones', () => {
    expect(parseCameraDate('2024:07:01 14:03:22', '250', '+03:00')).toEqual({
      takenAt: Date.UTC(2024, 6, 1, 11, 3, 22, 250),
      takenOffset: 180,
    })
    expect(parseCameraDate('2022-12-31T23:30:00+0530')).toEqual({
      takenAt: Date.UTC(2022, 11, 31, 18, 0, 0),
      takenOffset: 330,
    })
    expect(parseCameraDate('2020-02-02T02:02:02Z')).toEqual({ takenAt: Date.UTC(2020, 1, 2, 2, 2, 2), takenOffset: 0 })
  })

  it('reads a date without a time zone as local time', () => {
    expect(parseCameraDate('2024:07:01 14:03:22')).toEqual({ takenAt: new Date(2024, 6, 1, 14, 3, 22).getTime() })
  })

  it('refuses placeholders and impossible dates', () => {
    expect(parseCameraDate('0000:00:00 00:00:00')).toBeUndefined()
    expect(parseCameraDate('4501:01:01 00:00:00')).toBeUndefined()
    expect(parseCameraDate('2023:02:30 10:00:00')).toBeUndefined()
    expect(parseCameraDate('not a date')).toBeUndefined()
  })
})

describe('dates in file names', () => {
  it('reads the names phones and apps give', () => {
    expect(dateFromFileName('IMG-20171218-WA0028.jpg')).toBe(new Date(2017, 11, 18).getTime())
    expect(dateFromFileName('Screenshot_20240101-101500.png')).toBe(new Date(2024, 0, 1, 10, 15, 0).getTime())
    expect(dateFromFileName('PXL_20240101_101500123.jpg')).toBe(new Date(2024, 0, 1, 10, 15, 0).getTime())
    expect(dateFromFileName('20230615_083000.jpg')).toBe(new Date(2023, 5, 15, 8, 30, 0).getTime())
    expect(dateFromFileName('2021-03-04 05.06.07.jpg')).toBe(new Date(2021, 2, 4, 5, 6, 7).getTime())
    expect(dateFromFileName('signal-2024-01-01-101500.jpg')).toBe(new Date(2024, 0, 1).getTime())
  })

  it('ignores names without a plausible date', () => {
    expect(dateFromFileName('IMG_0001.jpg')).toBeUndefined()
    expect(dateFromFileName('holiday.jpg')).toBeUndefined()
    expect(dateFromFileName('19800101_000000.jpg')).toBeUndefined()
    expect(dateFromFileName('29990101.jpg')).toBeUndefined()
  })
})

describe('photos', () => {
  it('reads date, time zone, place, turned size and camera', async () => {
    const facts = await readImageFacts(await fixture('photo.jpg', 'image/jpeg'))
    expect(facts.taken).toEqual({ takenAt: Date.UTC(2024, 6, 1, 11, 3, 22, 250), takenOffset: 180 })
    expect(facts.lat).toBeCloseTo(41.0082, 4)
    expect(facts.lon).toBeCloseTo(28.9784, 4)
    // Stored 16×8, shown turned a quarter (orientation 6).
    expect([facts.width, facts.height]).toEqual([8, 16])
    expect(facts.camera).toBe('Apple iPhone 15')
  })

  it('gives nothing for an image without tags', async () => {
    const facts = await readImageFacts(await fixture('plain.png', 'image/png'))
    expect(facts.taken).toBeUndefined()
    expect(facts.lat).toBeUndefined()
    expect([facts.width, facts.height]).toEqual([4, 4])
  })
})

describe('videos', () => {
  it('reads an MP4: creation time, place, size and length', async () => {
    const facts = await readVideoFacts(await fixture('clip.mp4', 'video/mp4'))
    expect(facts.taken).toEqual({ takenAt: Date.UTC(2023, 4, 6, 7, 8, 9) })
    expect(facts.lat).toBeCloseTo(48.8584, 4)
    expect(facts.lon).toBeCloseTo(2.2945, 4)
    expect([facts.width, facts.height]).toEqual([64, 48])
    expect(facts.durationMs).toBeGreaterThanOrEqual(1400)
    expect(facts.durationMs).toBeLessThanOrEqual(1600)
  })

  it("reads Apple's keys: the date with its time zone, and the place", async () => {
    const facts = await readVideoFacts(await fixture('apple.mov', 'video/quicktime'))
    expect(facts.taken).toEqual({ takenAt: Date.UTC(2022, 11, 31, 18, 0, 0), takenOffset: 330 })
    expect(facts.lat).toBeCloseTo(35.6762, 4)
    expect(facts.lon).toBeCloseTo(139.6503, 4)
  })

  it('reads ISO 6709 and refuses nonsense', () => {
    expect(parseIso6709('+41.0082+028.9784+012.000/')).toEqual({ lat: 41.0082, lon: 28.9784 })
    expect(parseIso6709('-33.8688+151.2093/')).toEqual({ lat: -33.8688, lon: 151.2093 })
    expect(parseIso6709('+00.0000+000.0000/')).toBeUndefined()
    expect(parseIso6709('+95.0+10.0/')).toBeUndefined()
    expect(parseIso6709('here')).toBeUndefined()
  })

  it('stops at a file that is not a video', async () => {
    expect(await readVideoFacts(new Blob([new Uint8Array(3)]))).toEqual({})
    expect(await readVideoFacts(await fixture('photo.jpg', 'image/jpeg'))).toEqual({})
  })
})

describe('readMedia', () => {
  it('is only for photos and videos', async () => {
    expect(mediaKindOf('a.HEIC')).toBe('image')
    expect(mediaKindOf('a.bin', 'video/mp4')).toBe('video')
    expect(mediaKindOf('drawing.svg', 'image/svg+xml')).toBeNull()
    expect(mediaKindOf('notes.md', 'text/markdown')).toBeNull()
    expect(await readMedia(new File(['hi'], 'notes.md', { type: 'text/markdown' }))).toBeUndefined()
  })

  it('puts it together, with a content hash', async () => {
    const media = await readMedia(await fixture('photo.jpg', 'image/jpeg', Date.UTC(2025, 0, 1)))
    expect(media).toMatchObject({
      takenAt: Date.UTC(2024, 6, 1, 11, 3, 22, 250),
      takenOffset: 180,
      takenFrom: 'exif',
      width: 8,
      height: 16,
      camera: 'Apple iPhone 15',
    })
    expect(media?.hash).toMatch(/^[A-Za-z0-9+/]{43}=$/)
  })

  it('falls back to the name, then the file date', async () => {
    const bytes = await readFile(new URL('./fixtures/plain.png', import.meta.url))
    const named = await readMedia(new File([bytes], 'IMG-20171218-WA0028.png', { type: 'image/png', lastModified: 5 }))
    expect(named).toMatchObject({ takenAt: new Date(2017, 11, 18).getTime(), takenFrom: 'filename' })
    const dated = await readMedia(new File([bytes], 'x.png', { type: 'image/png', lastModified: Date.UTC(2020, 0, 1) }))
    expect(dated).toMatchObject({ takenAt: Date.UTC(2020, 0, 1), takenFrom: 'file' })
  })
})
