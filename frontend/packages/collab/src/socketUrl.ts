import { deviceTicket } from '@kutup/session/devices'
import { withClientParam } from '@kutup/session/clientVersion'
import { getOrCreateTabId } from './identity'

/**
 * The collab WebSocket for a file, with a single-use ticket for `device`
 * (`POST /api/v1/account/devices/tickets`: a browser can't set the device header on a
 * socket), naming this tab (`getOrCreateTabId`): the room's peer list
 * carries it. Asked again before every connect, reconnects included: a ticket
 * is good once, for a minute. `/api` is same-origin in every Kutup web app.
 */
export async function collabSocketUrl(device: { header: string }, base: string): Promise<string> {
  const ticket = await deviceTicket(device.header)
  const origin = window.location.origin.replace(/^http/, 'ws')
  // A file on another server: its route through this one (the same suffix).
  return withClientParam(`${origin}/api${base}/collab/ws?ticket=${encodeURIComponent(ticket)}&tab=${getOrCreateTabId()}`)
}
