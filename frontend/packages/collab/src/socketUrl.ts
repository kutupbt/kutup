import { freshAccessToken } from '@kutup/session/client'

/**
 * The collab WebSocket for a file on this app's own origin (`/api` is
 * same-origin in every Kutup web app), with a token fresh enough to connect.
 */
export async function collabSocketUrl(fileId: string, deviceId: number, base = `/files/${encodeURIComponent(fileId)}`): Promise<string> {
  const token = await freshAccessToken()
  const origin = window.location.origin.replace(/^http/, 'ws')
  // A file on another server: its route through this one (the same suffix).
  return `${origin}/api${base}/collab/ws?token=${encodeURIComponent(token)}&deviceId=${deviceId}`
}
