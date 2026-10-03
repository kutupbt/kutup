export function normalizeAudioWaveform(
  channels: readonly Float32Array[],
  sampleCount: number,
): Uint8Array {
  if (!Number.isSafeInteger(sampleCount) || sampleCount < 1 || sampleCount > 1024) {
    throw new Error('invalid waveform sample count')
  }
  if (channels.length === 0 || channels.some(channel => channel.length === 0)) {
    throw new Error('audio has no samples')
  }
  const frameCount = Math.min(...channels.map(channel => channel.length))
  const peaks = new Float64Array(sampleCount)
  for (let bucket = 0; bucket < sampleCount; bucket += 1) {
    const start = Math.floor(bucket * frameCount / sampleCount)
    const end = Math.max(start + 1, Math.floor((bucket + 1) * frameCount / sampleCount))
    let sumSquares = 0
    let values = 0
    for (const channel of channels) {
      for (let frame = start; frame < Math.min(end, frameCount); frame += 1) {
        const value = Number.isFinite(channel[frame]) ? Math.max(-1, Math.min(1, channel[frame])) : 0
        sumSquares += value * value
        values += 1
      }
    }
    peaks[bucket] = values ? Math.sqrt(sumSquares / values) : 0
  }
  let maximum = 0
  for (const peak of peaks) maximum = Math.max(maximum, peak)
  const output = new Uint8Array(sampleCount)
  if (maximum === 0) return output
  for (let index = 0; index < peaks.length; index += 1) {
    output[index] = Math.min(255, Math.round(peaks[index] / maximum * 255))
  }
  return output
}
