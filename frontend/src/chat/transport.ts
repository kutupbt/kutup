import axios from 'axios'
import api from '@/api/client'
import type { ChatTransportPort } from './types'

/** Authenticated REST adapter consumed by the Rust engine. */
export class ApiChatTransport implements ChatTransportPort {
  async registerDevice(request: unknown): Promise<unknown> {
    return api.post('/chat/device', request).then((response) => response.data)
  }

  async fetchBundles(username: string): Promise<unknown> {
    return api
      .get(`/chat/users/${encodeURIComponent(username)}/keys`)
      .then((response) => response.data)
  }

  async fetchSyncBundles(username: string, currentDeviceId: number): Promise<unknown> {
    return api
      .get(`/chat/users/${encodeURIComponent(username)}/keys`, {
        params: { syncDeviceId: currentDeviceId },
      })
      .then((response) => response.data)
  }

  async fetchManifest(username: string): Promise<unknown | null> {
    try {
      return await api
        .get(`/chat/users/${encodeURIComponent(username)}/manifest`)
        .then((response) => response.data)
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 404) return null
      throw error
    }
  }

  async publishManifest(manifest: unknown): Promise<unknown> {
    return api.post('/chat/manifest', manifest).then((response) => response.data)
  }

  async prekeyCount(deviceId: number): Promise<unknown> {
    return api
      .get('/chat/keys/count', { params: { deviceId } })
      .then((response) => response.data)
  }

  async replenishPrekeys(deviceId: number, request: unknown): Promise<void> {
    await api.put('/chat/keys', request, { params: { deviceId } })
  }

  async sendMessage(
    username: string,
    request: unknown,
  ): Promise<
    | { kind: 'delivered'; deduplicated?: boolean }
    | { kind: 'mismatch'; mismatch: unknown }
  > {
    try {
      const response = await api.post(
        `/chat/users/${encodeURIComponent(username)}/messages`,
        request,
      )
      return {
        kind: 'delivered',
        deduplicated: response.data?.deduplicated === true,
      }
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 409) {
        return { kind: 'mismatch', mismatch: error.response.data }
      }
      throw error
    }
  }

  async sendSyncMessage(
    request: unknown,
  ): Promise<
    | { kind: 'delivered'; deduplicated?: boolean }
    | { kind: 'mismatch'; mismatch: unknown }
  > {
    try {
      const response = await api.post('/chat/sync/messages', request)
      return {
        kind: 'delivered',
        deduplicated: response.data?.deduplicated === true,
      }
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 409) {
        return { kind: 'mismatch', mismatch: error.response.data }
      }
      throw error
    }
  }

  async drainMailbox(deviceId: number, after: string | null, limit: number): Promise<unknown> {
    return api
      .get('/chat/messages', {
        params: { deviceId, ...(after ? { after } : {}), limit },
      })
      .then((response) => response.data)
  }

  async ackMessages(deviceId: number, ids: string[]): Promise<void> {
    await api.post('/chat/messages/ack', { ids }, { params: { deviceId } })
  }
}
