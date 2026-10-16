import axios from 'axios'
import { accountOfKey } from '@kutup/crypto/accountRef'
import { accountHead, NotInVerifiedIndexError } from '@kutup/session/accountHead'
import api from '@kutup/session/client'
import { getSession } from '@kutup/session/store'
import { apiBase } from '@kutup/session/apiBase'
import type {
  ChatDevice,
  ChatTransportPort,
  InviteLinkOperation,
  InviteLinkResult,
  MlsInvitationDecision,
  MlsInvitationDecisionResponse,
  MlsInvitationFeedback,
  MlsIncarnationRecovery,
  MlsMailboxPage,
  PendingMlsInvitation,
  RecoverMlsConversationRequest,
} from './types'

/**
 * A Chat route for one account, given as its `aci:<uuid>@<server>` string:
 * `/chat/accounts/<accountId><suffix>` with the server as a parameter. The
 * engine hands accounts only; an address never reaches a route.
 */
export function accountRoute(
  account: string,
  suffix: string,
  scope: '/chat' | '/chat/anonymous' = '/chat',
): { path: string; server: string } {
  const ref = accountOfKey(account)
  if (!ref) throw new Error('not an account reference')
  return { path: `${scope}/accounts/${encodeURIComponent(ref.accountId)}${suffix}`, server: ref.server }
}

function signedIn() {
  const session = getSession()
  if (!session) throw new Error('not signed in')
  return session
}

/** Authenticated REST adapter consumed by the Rust engine. */
/** Extra waits for an ordering quorum, after the API client's own retries. */
const QUORUM_RETRY_DELAYS_MS = [3_000, 6_000]

export class ApiChatTransport implements ChatTransportPort {
  async listDevices(): Promise<ChatDevice[]> {
    return api
      .get<{ devices: ChatDevice[] }>('/chat/device')
      .then((response) => response.data.devices)
  }

  async revokeDevice(deviceId: number): Promise<void> {
    await api.delete(`/chat/device/${deviceId}`)
  }

  async renameDevice(deviceId: number, name: string): Promise<void> {
    await api.patch(`/chat/device/${deviceId}`, { name })
  }

  async registerDevice(request: unknown): Promise<unknown> {
    return api.post('/chat/device', request).then((response) => response.data)
  }

  async fetchBundles(account: string): Promise<unknown> {
    const { path, server } = accountRoute(account, '/keys')
    return api
      .get(path, { params: { server } })
      .then((response) => response.data)
  }

  async fetchSyncBundles(
    account: string,
    currentDeviceId: number,
  ): Promise<unknown> {
    const { path, server } = accountRoute(account, '/keys')
    return api
      .get(path, {
        params: { syncDeviceId: currentDeviceId, server },
      })
      .then((response) => response.data)
  }

  async fetchMlsOrderingPolicy(domain: string): Promise<unknown> {
    return api
      .get(`/chat/mls/domains/${encodeURIComponent(domain)}/policy`)
      .then((response) => response.data)
  }

  async fetchManifest(account: string): Promise<unknown | null> {
    const { path, server } = accountRoute(account, '/manifest')
    try {
      return await api
        .get(path, { params: { server } })
        .then((response) => response.data)
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 404) return null
      throw error
    }
  }

  async fetchManifestHistory(
    account: string,
    fromSequence: string,
    toSequence: string,
    pageFromSequence: string,
  ): Promise<unknown> {
    const { path, server } = accountRoute(account, '/manifest-history')
    return api
      .get(path, {
        params: {
          server,
          fromSequence,
          toSequence,
          pageFromSequence,
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
    account: string,
    capability: string,
  ): Promise<unknown> {
    const { path, server } = accountRoute(account, '/keys', '/chat/anonymous')
    return axios
      .post(
        `${apiBase()}${path}`,
        { capability },
        { params: { server }, withCredentials: false, headers: { Authorization: undefined } },
      )
      .then((response) => response.data)
  }

  async publishManifest(manifest: unknown): Promise<unknown> {
    return api.post('/chat/manifest', manifest).then((response) => response.data)
  }

  /**
   * The account's synced identity pins, shared with Drive
   * (docs/plans/drive-identity-pins.md), held to the account head
   * (docs/plans/rollback-protection.md): the revision the server names must
   * be the one the verified index lists, and the engine checks the sealed one
   * against it. A list the head does not vouch for, or an app blocked on
   * another history, throws: Chat keeps to its own pins, and the shell's
   * banner says why.
   */
  async fetchIdentityPins(): Promise<{ revision: number; envelope: string } | null> {
    const head = await accountHead(signedIn())
    // Two reads: a write landing between them is read again once.
    for (let attempt = 0; ; attempt++) {
      const index = await head.verifiedIndex('pins')
      let record: { revision: number; envelope: string } | null
      try {
        record = await api.get<{ revision: number; envelope: string }>('/user/identity-pins').then((response) => response.data)
      } catch (error) {
        if (!(axios.isAxiosError(error) && error.response?.status === 404)) throw error
        record = null
      }
      try {
        if (record) index.expect('pins', record.revision)
        else index.expectListing([])
        return record
      } catch (error) {
        if (!(error instanceof NotInVerifiedIndexError) || attempt > 0) throw error
      }
    }
  }

  /**
   * Stores the engine's next list with the next account head. `false` when
   * another app stored a list first (the engine reads it again and redoes its
   * change); sent again on a new head when only another value moved; a
   * write whose answer was lost is found in the index and counts as stored.
   */
  async storeIdentityPins(write: { baseRevision: number; envelope: string; revision: number }): Promise<boolean> {
    let stored = false
    await (await accountHead(signedIn())).listedWrite('pins', (index) => {
      const listed = index.revision('pins') ?? 0
      if (listed === write.revision) {
        stored = true
        return Promise.resolve(null)
      }
      if (listed !== write.baseRevision) return Promise.resolve(null)
      return Promise.resolve({
        changes: [['pins', write.revision]] as const,
        send: async (head: string) => {
          await api.put('/user/identity-pins', { baseRevision: write.baseRevision, envelope: write.envelope, head })
          stored = true
        },
      })
    })
    return stored
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
    account: string,
    version: string,
    accessKey: string,
  ): Promise<unknown | null> {
    const { path, server } = accountRoute(account, `/profile/${encodeURIComponent(version)}`)
    try {
      return await api
        .get(
          path,
          { params: { server }, headers: { 'X-Kutup-Profile-Access-Key': accessKey } },
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

  /**
   * A quorum certificate for a control block. 503 means an ordering server
   * declined to vote, usually because it is one block behind the others and
   * still replicating it; the API client's short retry window is not always
   * enough, so this waits a little longer before giving up.
   */
  async collectMlsOrderingVotes(request: unknown): Promise<unknown> {
    for (let attempt = 0; ; attempt++) {
      try {
        return (await api.post('/chat/mls/control/votes', request)).data
      } catch (error) {
        const quorumUnavailable = axios.isAxiosError(error) && error.response?.status === 503
        if (!quorumUnavailable || attempt >= QUORUM_RETRY_DELAYS_MS.length) throw error
        await new Promise((resolve) => setTimeout(resolve, QUORUM_RETRY_DELAYS_MS[attempt]))
      }
    }
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
  ): Promise<{
    bytes: Uint8Array
    entryCount: number
    nextHeight?: string
    genesisGroupId: string
  }> {
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
    const genesis = record?.genesis
    const genesisGroupId = typeof genesis === 'object'
      && genesis !== null
      && 'mlsGroupId' in genesis
      && typeof genesis.mlsGroupId === 'string'
      ? genesis.mlsGroupId
      : null
    const entryCount = record && Array.isArray(record.commits)
      ? record.commits.length
      : -1
    if (
      entryCount < 0
      || entryCount > 64
      || genesisGroupId === null
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
      genesisGroupId,
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

  async callInviteLink(host: string, operation: InviteLinkOperation): Promise<InviteLinkResult> {
    return api
      .post<InviteLinkResult>('/chat/invite-links', { host, operation })
      .then((response) => response.data)
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
    account: string,
    request: unknown,
  ): Promise<
    | { kind: 'delivered'; deduplicated?: boolean }
    | { kind: 'mismatch'; mismatch: unknown }
  > {
    const { path, server } = accountRoute(account, '/messages')
    try {
      const response = await api.post(path, request, { params: { server } })
      return {
        kind: 'delivered',
        deduplicated: response.data?.deduplicated === true,
      }
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 409) {
        return { kind: 'mismatch', mismatch: error.response.data }
      }
      throw peerSendError(error)
    }
  }

  async sendSealedMessage(
    account: string,
    request: unknown,
  ): Promise<
    | { kind: 'delivered'; deduplicated?: boolean }
    | { kind: 'mismatch'; mismatch: unknown }
    | { kind: 'refused' }
  > {
    const { path, server } = accountRoute(account, '/messages', '/chat/anonymous')
    try {
      const response = await axios.post(
        `${apiBase()}${path}`,
        request,
        { params: { server }, withCredentials: false, headers: { Authorization: undefined } },
      )
      return { kind: 'delivered', deduplicated: response.data?.deduplicated === true }
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 409) {
        return { kind: 'mismatch', mismatch: error.response.data }
      }
      // The server's uniform refusal: the recipient no longer takes this
      // capability. Only its exact answer counts, not a proxy's 404.
      if (axios.isAxiosError(error) && error.response?.status === 404 && isSealedRefusal(error.response.data)) {
        return { kind: 'refused' }
      }
      // The recipient's server refused this message for good
      // (docs/federation-protocol.md): it leaves the queue as a refusal does.
      if (axios.isAxiosError(error) && error.response?.status === 502 && errorCode(error) === 'peerRefused') {
        return { kind: 'refused' }
      }
      throw peerSendError(error)
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

function isSealedRefusal(body: unknown): boolean {
  return typeof body === 'object' && body !== null && (body as { error?: unknown }).error === 'sealed delivery unavailable'
}

function errorCode(error: unknown): string | undefined {
  return axios.isAxiosError(error)
    ? (error.response?.data as { code?: unknown } | undefined)?.code as string | undefined
    : undefined
}

/**
 * The recipient's server does not speak this Chat wire yet (503
 * `peerUnsupported`): the message waits, in order, until it does. The error
 * names the code so the queue's failure report says why.
 */
export const PEER_UNSUPPORTED = 'peerUnsupported'

function peerSendError(error: unknown): unknown {
  if (axios.isAxiosError(error) && error.response?.status === 503 && errorCode(error) === PEER_UNSUPPORTED) {
    return new Error(`${PEER_UNSUPPORTED}: the recipient's server does not support this Chat version yet`)
  }
  return error
}
