import { getCryptoWasm, type LiveLocationUpdate } from './rustWasm'

export type { LiveLocationUpdate }

/** A position to share: degrees, accuracy in metres, when it was read. */
export interface LiveLocationPosition {
  lat: number
  lon: number
  accuracyM: number
  atMs: number
}

/**
 * Seal update number `counter` of a live-location stream (docs/plans/maps.md):
 * 88 bytes, standard base64, bound to the stream and the counter.
 */
export async function sealLiveLocationUpdate(
  keyBase64: string,
  streamIdHex: string,
  counter: number,
  position: LiveLocationPosition,
): Promise<string> {
  const module = await getCryptoWasm()
  return module.liveLocationSeal(
    keyBase64,
    streamIdHex,
    counter,
    position.lat,
    position.lon,
    Math.max(0, Math.min(100_000, Math.round(position.accuracyM))),
    Math.round(position.atMs),
  )
}

/** Open an update of this stream; throws when it is not one. */
export async function openLiveLocationUpdate(keyBase64: string, streamIdHex: string, envelopeBase64: string): Promise<LiveLocationUpdate> {
  const module = await getCryptoWasm()
  return module.liveLocationOpen(keyBase64, streamIdHex, envelopeBase64)
}
