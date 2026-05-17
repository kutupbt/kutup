import { describe, it, expect } from 'vitest'
import { formatBytes, formatSpeed } from './format'

describe('formatBytes', () => {
  it('returns bytes under 1 KiB', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(512)).toBe('512 B')
    expect(formatBytes(1023)).toBe('1023 B')
  })

  it('returns KB between 1 KiB and 1 MiB', () => {
    expect(formatBytes(1024)).toBe('1.0 KB')
    expect(formatBytes(1536)).toBe('1.5 KB')
    expect(formatBytes(1024 * 1024 - 1)).toBe('1024.0 KB')
  })

  it('returns MB between 1 MiB and 1 GiB', () => {
    expect(formatBytes(1024 * 1024)).toBe('1.0 MB')
    expect(formatBytes(5 * 1024 * 1024 + 512 * 1024)).toBe('5.5 MB')
  })

  it('returns GB between 1 GiB and 1 TiB', () => {
    expect(formatBytes(1024 * 1024 * 1024)).toBe('1.00 GB')
    expect(formatBytes(2.5 * 1024 * 1024 * 1024)).toBe('2.50 GB')
  })

  it('returns TB between 1 TiB and 1 PiB', () => {
    const TiB = 1024 ** 4
    expect(formatBytes(TiB)).toBe('1.00 TB')
    expect(formatBytes(57.07 * TiB)).toBe('57.07 TB')
    expect(formatBytes(1024 ** 5 - 1)).toBe('1024.00 TB')
  })

  it('returns PB at 1 PiB and above', () => {
    const PiB = 1024 ** 5
    expect(formatBytes(PiB)).toBe('1.00 PB')
    expect(formatBytes(3 * PiB)).toBe('3.00 PB')
  })
})

describe('formatSpeed', () => {
  it('returns empty string for zero / negative', () => {
    expect(formatSpeed(0)).toBe('')
    expect(formatSpeed(-1)).toBe('')
  })

  it('formats sub-KB as B/s', () => {
    expect(formatSpeed(500)).toBe('500 B/s')
  })

  it('formats KB/s and MB/s with one decimal', () => {
    expect(formatSpeed(1024)).toBe('1.0 KB/s')
    expect(formatSpeed(2 * 1024 * 1024)).toBe('2.0 MB/s')
    expect(formatSpeed(1024 * 1024 + 512 * 1024)).toBe('1.5 MB/s')
  })
})
