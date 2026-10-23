import api from '@kutup/session/client'
import { resolveApiBase } from '@kutup/session/apiBase'
import type { WasmLinkingDeviceHandle } from './types'

/** The socket closed because its link code expired (the server's lifetime). */
export const PROVISIONING_EXPIRED = 4408

export interface ProvisioningCallbacks {
  /** The `kutup://link?…` code to show, as a QR code and as text. */
  onCode(code: string): void
  /** The linking device's sealed message arrived. */
  onEnvelope(envelope: unknown): void
  /** The code expired before another device used it: show a new one. */
  onExpired(): void
  onError(error: unknown): void
}

/**
 * The new device's side of linking (docs/plans/account-identity-key.md):
 * a provisioning ticket (signed in, no device yet), then the provisioning
 * socket, which gives this browser an address for the code and relays the
 * one envelope a device of the account sends to it. Returns a function that
 * closes the socket.
 */
export async function openProvisioning(
  linking: WasmLinkingDeviceHandle,
  callbacks: ProvisioningCallbacks,
): Promise<() => void> {
  const ticket = await api
    .post<{ ticket: string }>('/chat/provisioning/ticket')
    .then((response) => response.data.ticket)
  const base = await resolveApiBase()
  const url = new URL(`${base.replace(/\/$/, '')}/chat/provisioning`, window.location.href)
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
  url.searchParams.set('ticket', ticket)
  const socket = new WebSocket(url)
  let delivered = false
  let closedByUs = false
  socket.onmessage = (event: MessageEvent) => {
    let message: { type?: string; address?: unknown; envelope?: unknown }
    try {
      message = JSON.parse(String(event.data))
    } catch (error) {
      callbacks.onError(error)
      return
    }
    try {
      if (message.type === 'address' && typeof message.address === 'string') {
        callbacks.onCode(linking.linkCode(message.address))
      } else if (message.type === 'envelope' && !delivered) {
        delivered = true
        callbacks.onEnvelope(message.envelope)
      }
    } catch (error) {
      callbacks.onError(error)
    }
  }
  socket.onclose = (event: CloseEvent) => {
    if (closedByUs || delivered) return
    if (event.code === PROVISIONING_EXPIRED) callbacks.onExpired()
    else callbacks.onError(new Error(`provisioning socket closed (${event.code})`))
  }
  return () => {
    closedByUs = true
    socket.close()
  }
}
