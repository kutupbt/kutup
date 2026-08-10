import { describe, expect, it } from 'vitest'
import { normalizeAudioWaveform } from './waveform'

describe('audio waveform normalization', () => {
  it('produces deterministic unsigned normalized RMS samples', () => {
    const channel = Float32Array.from([0, 0, 0.25, -0.25, 0.5, -0.5, 1, -1])
    const result = normalizeAudioWaveform([channel], 4)
    expect(result).toEqual(Uint8Array.from([0, 64, 128, 255]))
  })

  it('mixes channels and handles silence and non-finite values', () => {
    expect(normalizeAudioWaveform([
      new Float32Array([0, Number.NaN, 0, 0]),
      new Float32Array([0, 0, 0, 0]),
    ], 2)).toEqual(new Uint8Array(2))
  })

  it('rejects empty input and unreasonable sample counts', () => {
    expect(() => normalizeAudioWaveform([], 64)).toThrow(/no samples/)
    expect(() => normalizeAudioWaveform([new Float32Array([1])], 0)).toThrow(/sample count/)
    expect(() => normalizeAudioWaveform([new Float32Array([1])], 1025)).toThrow(/sample count/)
  })
})
