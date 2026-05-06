import api from './client'

export interface DeviceRow {
  deviceId: number
  label: string
  isActive: boolean
  createdAt: string
  lastSeenAt: string | null
}

export async function registerDevice(
  publicSigningB64: string,
  label: string,
): Promise<{ deviceId: number }> {
  // authSig: empty in v1 — JWT is the trust anchor; AuthSig is recorded for v2 hardening.
  const r = await api.post('/devices', {
    publicSigning: publicSigningB64,
    label,
    authSig: '',
    timestamp: Math.floor(Date.now() / 1000),
  })
  return r.data
}

export async function listDevices(): Promise<DeviceRow[]> {
  const r = await api.get<DeviceRow[]>('/devices')
  return r.data
}

export async function revokeDevice(id: number): Promise<void> {
  await api.delete(`/devices/${id}`)
}

export interface VersionRow {
  id: string
  s3VersionId: string
  storagePath: string
  seqAtSnapshot: number
  docKeyId: number
  authorUserId: string
  sizeBytes: number
  label: string | null
  keepForever: boolean
  createdAt: string
}

export async function listVersions(fileId: string): Promise<VersionRow[]> {
  const r = await api.get<VersionRow[]>(`/files/${fileId}/versions`)
  return r.data
}

export function getVersionDownloadUrl(fileId: string, vid: string): string {
  // Includes /api prefix because this URL is consumed directly (e.g. anchor href),
  // not via the axios instance which adds the baseURL itself.
  return `/api/files/${fileId}/versions/${vid}/download`
}

export async function patchVersion(
  fileId: string,
  vid: string,
  patch: { label?: string; keepForever?: boolean },
): Promise<VersionRow> {
  const r = await api.patch<VersionRow>(`/files/${fileId}/versions/${vid}`, patch)
  return r.data
}

/**
 * Claim the first-seeder slot for a fresh collab file. Server runs an
 * atomic UPDATE; exactly one caller for a given file ever gets
 * `committed: true`. Used by TextCollabEditor's cold-start to avoid two
 * tabs both inserting `initialContent` and CRDT-merging into duplicate.
 *
 * Idempotent — once committed, all later callers (including from new
 * tab sessions) see committed=false and must wait for WS replay to
 * populate their local Y.Text.
 */
export async function claimSeed(fileId: string): Promise<{ committed: boolean }> {
  const r = await api.post<{ committed: boolean }>(`/files/${fileId}/claim-seed`)
  return r.data
}
