import axios from 'axios'
import api from '@/api/client'
import { apiBase } from '@/lib/apiBase'
import type {
  ChatTransportPort,
  MlsInvitationDecision,
  MlsInvitationDecisionResponse,
  MlsInvitationFeedback,
  MlsIncarnationRecovery,
  MlsMailboxPage,
  PendingMlsInvitation,
  RecoverMlsConversationRequest,
} from './types'

/** Authenticated REST adapter consumed by the Rust engine. */
export class ApiChatTransport implements ChatTransportPort {
  async registerDevice(request: unknown): Promise<unknown> {
    return api.post('/chat/device', request).then((response) => response.data)
  }

  async fetchBundles(username: string, transparencyTreeSize: string): Promise<unknown> {
    return api
      .get(`/chat/users/${encodeURIComponent(username)}/keys`, {
        params: { transparencyTreeSize },
      })
      .then((response) => response.data)
  }

  async fetchSyncBundles(
    username: string,
    currentDeviceId: number,
    transparencyTreeSize: string,
  ): Promise<unknown> {
    return api
      .get(`/chat/users/${encodeURIComponent(username)}/keys`, {
        params: { syncDeviceId: currentDeviceId, transparencyTreeSize },
      })
      .then((response) => response.data)
  }

  async fetchTransparencyCheckpoint(
    scope: string,
    fromTreeSize: string,
  ): Promise<unknown> {
    const path = scope === 'local'
      ? '/chat/transparency/checkpoint'
      : `/chat/transparency/domains/${encodeURIComponent(scope)}/checkpoint`
    return api
      .get(path, { params: { fromTreeSize } })
      .then((response) => response.data)
  }

  async fetchTransparencyPolicy(domain: string): Promise<unknown> {
    return api
      .get(`/chat/transparency/domains/${encodeURIComponent(domain)}/policy`)
      .then((response) => response.data)
  }

  async fetchMlsOrderingPolicy(domain: string): Promise<unknown> {
    return api
      .get(`/chat/mls/domains/${encodeURIComponent(domain)}/policy`)
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

  async fetchManifestPublication(
    username: string,
    transparencyTreeSize: string,
  ): Promise<unknown> {
    return api
      .get(`/chat/users/${encodeURIComponent(username)}/manifest-proof`, {
        params: { transparencyTreeSize },
      })
      .then((response) => response.data)
  }

  async fetchManifestRange(
    username: string,
    fromVersion: string,
    toVersion: string,
    pageFromVersion: string,
    cursor: string | null,
    transparencyTreeSize: string,
  ): Promise<unknown> {
    return api
      .get(`/chat/users/${encodeURIComponent(username)}/manifest-history`, {
        params: {
          fromVersion,
          toVersion,
          pageFromVersion,
          ...(cursor === null ? {} : { cursor }),
          transparencyTreeSize,
        },
      })
      .then((response) => response.data)
  }

  async fetchSealedSenderPolicy(domain: string): Promise<unknown> {
    return api
      .get(`/chat/sealed-sender/domains/${encodeURIComponent(domain)}/policy`)
      .then((response) => response.data)
  }

  async fetchSenderCertificate(deviceId: number): Promise<unknown> {
    return api
      .post('/chat/sealed-sender/certificate', undefined, { params: { deviceId } })
      .then((response) => response.data)
  }

  async fetchSealedBundles(
    username: string,
    capability: string,
    transparencyTreeSize: string,
  ): Promise<unknown> {
    return axios
      .post(
        `${apiBase()}/chat/anonymous/users/${encodeURIComponent(username)}/keys`,
        { capability, transparencyTreeSize },
        { withCredentials: false, headers: { Authorization: undefined } },
      )
      .then((response) => response.data)
  }

  async publishManifest(manifest: unknown, transparencyTreeSize: string): Promise<unknown> {
    return api
      .post('/chat/manifest', manifest, { params: { transparencyTreeSize } })
      .then((response) => response.data)
  }

  async fetchOwnProfile(): Promise<unknown | null> {
    try {
      return await api.get('/chat/profile').then((response) => response.data)
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 404) return null
      throw error
    }
  }

  async publishProfile(profile: unknown): Promise<unknown> {
    return api.put('/chat/profile', profile).then((response) => response.data)
  }

  async fetchProfile(
    username: string,
    version: string,
    accessKey: string,
  ): Promise<unknown | null> {
    try {
      return await api
        .get(
          `/chat/users/${encodeURIComponent(username)}/profile/${encodeURIComponent(version)}`,
          { headers: { 'X-Kutup-Profile-Access-Key': accessKey } },
        )
        .then((response) => response.data)
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 404) return null
      throw error
    }
  }

  async prekeyCount(deviceId: number): Promise<unknown> {
    return api
      .get('/chat/keys/count', { params: { deviceId } })
      .then((response) => response.data)
  }

  async replenishPrekeys(deviceId: number, request: unknown): Promise<void> {
    await api.put('/chat/keys', request, { params: { deviceId } })
  }

  async publishMlsKeyPackages(request: unknown): Promise<unknown> {
    return api.put('/chat/mls/key-packages', request).then((response) => response.data)
  }

  async mlsKeyPackageCount(deviceId: number): Promise<unknown> {
    return api
      .get(`/chat/mls/key-packages/${deviceId}/count`)
      .then((response) => response.data)
  }

  async createMlsConversation(request: unknown): Promise<unknown> {
    return api.post('/chat/mls/conversations', request).then((response) => response.data)
  }

  async recoverMlsConversation(request: RecoverMlsConversationRequest): Promise<unknown> {
    return api
      .post('/chat/mls/conversations/recover', request)
      .then((response) => response.data)
  }

  async fetchMlsRecovery(
    conversationId: string,
    incarnation: number,
  ): Promise<MlsIncarnationRecovery> {
    return api
      .get(
        `/chat/mls/conversations/${encodeURIComponent(conversationId)}/${incarnation}/recovery`,
      )
      .then((response) => response.data)
  }

  async stageMlsMembershipDelivery(request: unknown): Promise<unknown> {
    return api
      .put('/chat/mls/control/membership-deliveries', request)
      .then((response) => response.data)
  }

  async collectMlsOrderingVotes(request: unknown): Promise<unknown> {
    return api
      .post('/chat/mls/control/votes', request)
      .then((response) => response.data)
  }

  async commitMlsControlBlock(request: unknown): Promise<unknown> {
    return api
      .post('/chat/mls/control/blocks', request)
      .then((response) => response.data)
  }

  async fetchMlsControlHistory(
    conversationId: string,
    incarnation: number,
    afterHeight: string,
    limit = 64,
  ): Promise<{ bytes: Uint8Array; entryCount: number; nextHeight?: string }> {
    const response = await api.get(
      `/chat/mls/conversations/${encodeURIComponent(conversationId)}/${incarnation}/control-history`,
      {
        params: { afterHeight, limit },
        responseType: 'arraybuffer',
      },
    )
    const bytes = new Uint8Array(response.data as ArrayBuffer)
    let parsed: unknown
    try {
      parsed = JSON.parse(new TextDecoder().decode(bytes))
    } catch {
      throw new Error('server returned malformed MLS control-history JSON')
    }
    const record = typeof parsed === 'object' && parsed !== null
      ? parsed as Record<string, unknown>
      : null
    const nextHeight = record?.nextHeight
    const entryCount = record && Array.isArray(record.commits)
      ? record.commits.length
      : -1
    if (
      entryCount < 0
      || entryCount > 64
      || (
      nextHeight !== undefined
      && (
        typeof nextHeight !== 'string'
        || !/^[1-9][0-9]*$/.test(nextHeight)
      )
      )
    ) {
      throw new Error('server returned invalid MLS control-history pagination')
    }
    return {
      bytes,
      entryCount,
      ...(nextHeight === undefined ? {} : { nextHeight }),
    }
  }

  async listMlsInvitations(): Promise<PendingMlsInvitation[]> {
    return api.get('/chat/mls/invitations').then((response) => response.data)
  }

  async listMlsInvitationFeedback(): Promise<MlsInvitationFeedback[]> {
    return api.get('/chat/mls/invitation-feedback').then((response) => response.data)
  }

  async respondMlsInvitation(
    request: MlsInvitationDecision,
  ): Promise<MlsInvitationDecisionResponse> {
    return api.post('/chat/mls/invitations', request).then((response) => response.data)
  }

  async drainMlsMailbox(
    deviceId: number,
    after?: string,
    limit = 100,
  ): Promise<MlsMailboxPage> {
    return api
      .get(`/chat/mls/messages/${deviceId}`, {
        params: { after, limit },
      })
      .then((response) => response.data)
  }

  async ackMlsMailbox(deviceId: number, envelopeIds: string[]): Promise<void> {
    await api.post('/chat/mls/messages/ack', {
      deviceId,
      envelopeIds: [...envelopeIds].sort(),
    })
  }

  async publishMlsDeliveryCapability(request: unknown): Promise<void> {
    await api.put('/chat/mls/delivery-capability', request)
  }

  async fetchIdentifiedMlsKeyPackages(request: unknown): Promise<unknown> {
    return api
      .post('/chat/mls/key-packages/identified', request)
      .then((response) => response.data)
  }

  async fetchAnonymousMlsKeyPackages(request: unknown): Promise<unknown> {
    return axios
      .post(`${apiBase()}/chat/mls/anonymous/key-packages`, request, {
        withCredentials: false,
        headers: { Authorization: undefined },
      })
      .then((response) => response.data)
  }

  async submitAnonymousMlsMessage(request: unknown): Promise<unknown> {
    return axios
      .post(`${apiBase()}/chat/mls/anonymous/messages`, request, {
        withCredentials: false,
        headers: { Authorization: undefined },
      })
      .then((response) => response.data)
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

  async sendSealedMessage(
    username: string,
    request: unknown,
  ): Promise<
    | { kind: 'delivered'; deduplicated?: boolean }
    | { kind: 'mismatch'; mismatch: unknown }
  > {
    try {
      const response = await axios.post(
        `${apiBase()}/chat/anonymous/users/${encodeURIComponent(username)}/messages`,
        request,
        { withCredentials: false, headers: { Authorization: undefined } },
      )
      return { kind: 'delivered', deduplicated: response.data?.deduplicated === true }
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
