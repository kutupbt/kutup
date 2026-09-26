import axios from 'axios'
import { openLiveLocationUpdate, sealLiveLocationUpdate, type LiveLocationPosition, type LiveLocationUpdate } from '@kutup/crypto/liveLocation'
import api from '@kutup/session/client'

// A live location's stream on the sharer's server (docs/plans/maps.md): the
// server keeps only the latest sealed update; writing needs the write
// secret, reading the read capability, and neither is tied to an account.

const WRITE_HEADER = 'x-kutup-live-write'
const READ_HEADER = 'x-kutup-live-read'

export interface StreamSecrets {
  streamId: string
  key: string
  readCapability: string
  writeSecret: string
}

function randomBase64(bytes: number): string {
  const buffer = crypto.getRandomValues(new Uint8Array(bytes))
  return btoa(String.fromCharCode(...buffer))
}

function randomHex(bytes: number): string {
  return [...crypto.getRandomValues(new Uint8Array(bytes))].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/** A new stream on this account's server, open until `untilMs`. */
export async function createStream(untilMs: number): Promise<StreamSecrets> {
  const secrets: StreamSecrets = {
    streamId: randomHex(16),
    key: randomBase64(32),
    readCapability: randomBase64(32),
    writeSecret: randomBase64(32),
  }
  await api.post('/live-locations', {
    streamId: secrets.streamId,
    writeSecret: secrets.writeSecret,
    readCapability: secrets.readCapability,
    expiresAtMs: untilMs,
  })
  return secrets
}

export type WriteResult = 'written' | 'tooSoon' | 'gone'

/** Seal and store update number `counter`. */
export async function writeStream(secrets: StreamSecrets, counter: number, position: LiveLocationPosition): Promise<WriteResult> {
  const update = await sealLiveLocationUpdate(secrets.key, secrets.streamId, counter, position)
  try {
    await api.put(`/live-locations/${secrets.streamId}`, { update }, { headers: { [WRITE_HEADER]: secrets.writeSecret } })
    return 'written'
  } catch (error) {
    const status = axios.isAxiosError(error) ? error.response?.status : undefined
    if (status === 429 || status === 409) return 'tooSoon'
    if (status === 404) return 'gone'
    throw error
  }
}

/** End a stream now; a stream already gone is fine. */
export async function deleteStream(secrets: Pick<StreamSecrets, 'streamId' | 'writeSecret'>): Promise<void> {
  try {
    await api.delete(`/live-locations/${secrets.streamId}`, { headers: { [WRITE_HEADER]: secrets.writeSecret } })
  } catch (error) {
    if (!(axios.isAxiosError(error) && error.response?.status === 404)) throw error
  }
}

export interface StreamReading {
  update: LiveLocationUpdate | null
  /** When the server stored it. */
  updatedAtMs: number | null
}

/**
 * The latest position of a stream: through this server, which asks the
 * sharer's server when it is another one. Null when the stream is gone
 * (ended, or never readable with this capability).
 */
export async function readStream(
  stream: { server: string; streamId: string; key: string; readCapability: string },
  localServer: string,
): Promise<StreamReading | null> {
  try {
    const { data } = await api.get<{ update: string | null; updatedAtMs: number | null }>(`/live-locations/${stream.streamId}`, {
      headers: { [READ_HEADER]: stream.readCapability },
      params: stream.server === localServer ? undefined : { server: stream.server },
    })
    return {
      update: data.update ? await openLiveLocationUpdate(stream.key, stream.streamId, data.update) : null,
      updatedAtMs: data.updatedAtMs,
    }
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.status === 404) return null
    throw error
  }
}
