import axios from 'axios'
import { accountOfKey } from '@kutup/crypto/accountRef'
import { toBase64 } from '@kutup/crypto/base64'
import { exactBytes } from '@kutup/crypto/bytes'
import { accountHead } from '@kutup/session/accountHead'
import type { ScopeRecords } from '@kutup/session/accountRecords'
import api from '@kutup/session/client'
import { getSession } from '@kutup/session/store'
import { apiBase } from '@kutup/session/apiBase'
import { loadServerSettings } from '@kutup/session/apps'
import { setChatDeviceAuth } from './device-auth'
import type { ChatDevice, ChatTransportPort } from './types'

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

/**
 * This account doesn't talk to other servers (Settings → Privacy;
 * docs/plans/server-personal-data.md, A4): a send or a fetch that would reach
 * one is refused here. The server refuses the signed-in ones itself; the
 * sealed ones are anonymous to it, so this is where they stop.
 */
export class FederationOffError extends Error {
  constructor() {
    super('this account does not talk to other servers')
    this.name = 'FederationOffError'
  }
}

const FEDERATION_CHECK_MS = 60_000
let federationCache: { accountId: string; on: boolean; at: number } | null = null

/** Forgets what {@link federationOn} learnt: the next check asks again. */
export function forgetFederationState(): void {
  federationCache = null
}

/** Whether the signed-in account talks to other servers, asked at most once a minute. */
async function federationOn(): Promise<boolean> {
  const session = signedIn()
  const now = Date.now()
  if (federationCache && federationCache.accountId === session.accountId && now - federationCache.at < FEDERATION_CHECK_MS) {
    return federationCache.on
  }
  const { data } = await api.get<{ federation?: 'on' | 'off' }>('/user/me')
  const on = data.federation !== 'off'
  federationCache = { accountId: session.accountId, on, at: now }
  return on
}

/** Refuses with {@link FederationOffError} a request to another server while this account's federation is off. */
async function ensureMayReach(server: string): Promise<void> {
  // This server is the one the account's Chat lives on: its Chat name, not
  // the address's domain (a custom-domain address names another).
  const settings = await loadServerSettings<{ chat?: { serverName?: string | null } }>()
  const own = settings.chat?.serverName?.toLowerCase()
  if (own && server.toLowerCase() === own) return
  if (!(await federationOn())) throw new FederationOffError()
}

/** Authenticated REST adapter consumed by the Rust engine. */
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

  setDeviceAuth(deviceId: number, credential: string): void {
    setChatDeviceAuth(deviceId, credential)
  }

  async createLinkToken(): Promise<unknown> {
    return api.post('/chat/link-tokens').then((response) => response.data)
  }

  async relayProvisioning(address: string, request: unknown): Promise<boolean> {
    try {
      await api.put(`/chat/provisioning/${encodeURIComponent(address)}`, request)
      return true
    } catch (error) {
      // The new device's socket is gone (closed, expired, or not this
      // account's: one answer for all three).
      if (axios.isAxiosError(error) && error.response?.status === 404) return false
      throw error
    }
  }

  async distributeIdentity(
    request: unknown,
  ): Promise<{ kind: 'accepted' } | { kind: 'mismatch'; mismatch: unknown }> {
    try {
      await api.put('/chat/account-identity', request)
      return { kind: 'accepted' }
    } catch (error) {
      const status = axios.isAxiosError(error) ? error.response?.status : undefined
      if (axios.isAxiosError(error) && (status === 409 || status === 410)) {
        return { kind: 'mismatch', mismatch: error.response?.data }
      }
      throw error
    }
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

  /** The `session` hash this device's manifest entry carries: its sign-in, as the server works it out. */
  async fetchDeviceSession(): Promise<string> {
    return api
      .get<{ session: string }>('/device-session')
      .then((response) => response.data.session)
  }

  async fetchManifest(account: string): Promise<unknown | null> {
    const { path, server } = accountRoute(account, '/manifest')
    try {
      return await api
        .get(path, { params: { server } })
        .then((response) => response.data)
    } catch (error) {
      // Only the server's own "no manifest" (`404 noManifest`): another 404
      // (a proxy, Chat switched off) must not read as an account without a
      // Chat identity, which this device would then re-register.
      if (axios.isAxiosError(error) && error.response?.status === 404
        && (error.response.data as { code?: unknown } | undefined)?.code === 'noManifest') {
        return null
      }
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
    await ensureMayReach(server)
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
    // The pins are the one record of the account-records scope `pins`
    // (docs/plans/account-records.md): read with every page's head verified
    // and the scope checked against it.
    const copy = await (await accountHead(signedIn())).records('pins')
    return copy.records.get('pins') ?? null
  }

  /**
   * Stores the engine's next list with the next account head. `false` when
   * another app stored a list first (the engine reads it again and redoes its
   * change, or a revision it lists already).
   */
  async storeIdentityPins(write: { baseRevision: number; envelope: string; revision: number }): Promise<boolean> {
    const stored = await (await accountHead(signedIn())).recordsWrite('pins', (copy) => {
      const listed = copy.records.get('pins')?.revision ?? 0
      // Already at this revision: perhaps ours (an answer that was lost),
      // perhaps another device's at the same number. Not "stored": the
      // engine reads again and merges, which settles either case. Another
      // base: another app wrote first.
      if (listed === write.revision || listed !== write.baseRevision) return Promise.resolve(null)
      return Promise.resolve({ puts: [{ id: 'pins', revision: write.revision, envelope: write.envelope }], deletes: [], done: true })
    })
    return stored === true
  }

  /**
   * The account's group list (docs/plans/pairwise-groups.md §5): the
   * account-records scope `chatGroups` (docs/plans/account-records.md), read
   * as the head vouches for it (every page's head verified, the scope checked
   * against it); the engine checks each sealed revision against its entry's.
   * A list the head does not vouch for throws.
   */
  async fetchGroupList(): Promise<Array<{ id: string; revision: number; envelope: string }>> {
    return listed(await (await accountHead(signedIn())).records('chatGroups'))
  }

  /**
   * Stores one entry of the group list with the next account head. `false`
   * when the verified list holds another revision than `baseRevision`
   * (another device wrote first, or a revision listed already: the engine
   * reads the list again and merges).
   */
  async storeGroupEntry(write: { id: string; baseRevision: number; revision: number; envelope: string }): Promise<boolean> {
    return (await storeEntry('chatGroups', write)) === 'stored'
  }

  /**
   * The account's Chat contact list (docs/plans/chat-contacts-sync.md): the
   * account-records scope `chatContacts`, read like the group list.
   */
  async fetchContactList(): Promise<Array<{ id: string; revision: number; envelope: string }>> {
    return listed(await (await accountHead(signedIn())).records('chatContacts'))
  }

  /**
   * Stores one contact list entry with the next account head: `conflict`
   * when the verified list holds another revision than `baseRevision`
   * (another device wrote first, or a revision listed already: the engine
   * reads again and merges), `full` when the list holds as many entries as
   * it may (`scopeFull`).
   */
  async storeContactEntry(write: { id: string; baseRevision: number; revision: number; envelope: string }): Promise<'stored' | 'conflict' | 'full'> {
    try {
      return await storeEntry('chatContacts', write)
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 400 && (error.response.data as { code?: string } | undefined)?.code === 'scopeFull') {
        return 'full'
      }
      throw error
    }
  }

  /**
   * Removes one contact list entry at `baseRevision` (an eviction) with the
   * next account head; `false` when the verified list holds another
   * revision. Gone already counts as removed.
   */
  async deleteContactEntry(write: { id: string; baseRevision: number }): Promise<boolean> {
    const removed = await (await accountHead(signedIn())).recordsWrite('chatContacts', (copy) => {
      const listed = copy.records.get(write.id)?.revision
      if (listed === undefined) return Promise.resolve({ puts: [], deletes: [], done: true })
      if (listed !== write.baseRevision) return Promise.resolve(null)
      return Promise.resolve({ puts: [], deletes: [write.id], done: true })
    })
    return removed === true
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
    await ensureMayReach(server)
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

  /**
   * Sealed sends to several accounts of `server` in one anonymous request
   * (`SealedBatchSubmissionV1`): one result per recipient, in order.
   */
  async sendSealedBatch(server: string, request: unknown): Promise<unknown> {
    await ensureMayReach(server)
    try {
      const response = await axios.post(
        `${apiBase()}/chat/anonymous/messages/batch`,
        request,
        { params: { server }, withCredentials: false, headers: { Authorization: undefined } },
      )
      return response.data
    } catch (error) {
      throw peerSendError(error)
    }
  }

  /**
   * One group message to every listed account of `server`, sealed once, with
   * the group send token over them (`SealedMultiSubmissionV1`;
   * docs/plans/group-send-endorsements.md §3.4). `200`, `409` and `410` are
   * answers (who is over a budget, whose devices moved on); a token the
   * destination refuses (`401 groupSendTokenInvalid`), a destination that
   * didn't answer (`503`), a server without the route (`404`), or any status
   * the route doesn't define, sends those members pairwise. Only no answer at
   * all (offline) is an error.
   */
  async sendSealedMulti(
    server: string,
    request: unknown,
  ): Promise<
    | { kind: 'answered'; status: number; response: unknown }
    | { kind: 'peerUnavailable' }
    | { kind: 'tooLarge' }
    | { kind: 'rateLimited' }
    | { kind: 'tokenInvalid' }
  > {
    await ensureMayReach(server)
    try {
      const response = await axios.post(`${apiBase()}/chat/anonymous/messages/multi`, request, {
        params: { server },
        withCredentials: false,
        headers: { Authorization: undefined },
      })
      // Only a 200 stores; the engine sends the copies of any other status
      // pairwise.
      return { kind: 'answered', status: response.status, response: response.status === 200 ? response.data : {} }
    } catch (error) {
      if (axios.isAxiosError(error) && error.response) {
        const status = error.response.status
        if (status === 409 || status === 410) return { kind: 'answered', status, response: error.response.data }
        if (status === 401 && errorCode(error) === 'groupSendTokenInvalid') return { kind: 'tokenInvalid' }
        if (status === 503 || status === 404) return { kind: 'peerUnavailable' }
        if (status === 413) return { kind: 'tooLarge' }
        if (status === 429) return { kind: 'rateLimited' }
        // Any other status the route doesn't define: an answer that would
        // come back the same, so those copies go pairwise. Only no answer at
        // all (offline) is an error, which waits.
        return { kind: 'answered', status, response: {} }
      }
      throw peerSendError(error)
    }
  }

  /**
   * This account's group send endorsement for today, from its own server
   * (`GroupSendEndorsementResponseV1`; docs/plans/group-send-endorsements.md
   * §3.2). The engine checks it before keeping it.
   */
  async fetchGroupSendEndorsement(): Promise<unknown> {
    const response = await api.get('/chat/group-send/endorsement')
    return response.data
  }

  /**
   * The endorsement keys of this account's server, or of `server` from its
   * verified discovery (`GroupSendParamsV1`); `null` when that server
   * publishes none (`404`).
   */
  async fetchGroupSendParams(server?: string | null): Promise<unknown> {
    try {
      const response = await api.get('/chat/group-send/params', {
        params: server ? { server } : undefined,
      })
      return response.data
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 404) return null
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

  /**
   * A group home's gateway key config and identity history, through this
   * account's own server (docs/plans/pairwise-groups.md §3). The engine takes
   * them only through the group's pin.
   */
  async fetchGroupGateway(home: string, fromSequence: string): Promise<unknown> {
    return api
      .get('/chat/groups/gateway-key', { params: { server: home, fromSequence } })
      .then((response) => response.data)
  }

  /**
   * Relays a sealed group request through this account's own server, which
   * learns only which home it goes to. The answer stays sealed.
   */
  async relayGroupRequest(home: string, sealed: Uint8Array): Promise<GroupRelayOutcome> {
    try {
      // Exactly these bytes: `sealed` may be a view into the WASM memory.
      const response = await api.post<ArrayBuffer>(
        `/chat/groups/relay/${encodeURIComponent(home)}`,
        exactBytes(sealed),
        {
          headers: { 'Content-Type': 'message/ohttp-req' },
          responseType: 'arraybuffer',
        },
      )
      return { kind: 'answered', body: toBase64(new Uint8Array(response.data)) }
    } catch (error) {
      if (axios.isAxiosError(error)) {
        switch (error.response?.status) {
          // The home couldn't open it: an old key; the engine fetches it again.
          case 400:
            return { kind: 'unopenable' }
          case 429:
            return { kind: 'rateLimited' }
          case 502:
            return { kind: 'unreachable' }
          case 404:
            return { kind: 'groupsOff' }
          // This account's federation is off: a group homed elsewhere is
          // quiet for it until the switch is on again (it stays a member).
          case 403:
            if ((error.response.data as { code?: string } | undefined)?.code === 'federationOff') return { kind: 'groupsOff' }
            break
        }
      }
      throw error
    }
  }
}

/** What this account's server answered a relayed group request with. */
export type GroupRelayOutcome =
  | { kind: 'answered'; body: string }
  | { kind: 'unopenable' }
  | { kind: 'rateLimited' }
  | { kind: 'unreachable' }
  | { kind: 'groupsOff' }

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

/** A verified copy's records as the engine takes them. */
function listed(copy: ScopeRecords): Array<{ id: string; revision: number; envelope: string }> {
  return [...copy.records].map(([id, record]) => ({ id, revision: record.revision, envelope: record.envelope }))
}

/**
 * One entry stored on the verified copy with the next head: `conflict`
 * when the copy holds another revision than `baseRevision`, or the one being
 * stored already (perhaps ours, an answer that was lost; perhaps another
 * device's at the same number: the engine reads again and merges either way).
 */
async function storeEntry(
  scope: 'chatGroups' | 'chatContacts',
  write: { id: string; baseRevision: number; revision: number; envelope: string },
): Promise<'stored' | 'conflict'> {
  const stored = await (await accountHead(signedIn())).recordsWrite(scope, (copy) => {
    const listed = copy.records.get(write.id)?.revision ?? 0
    if (listed === write.revision || listed !== write.baseRevision) return Promise.resolve(null)
    return Promise.resolve({ puts: [{ id: write.id, revision: write.revision, envelope: write.envelope }], deletes: [], done: true })
  })
  return stored === true ? 'stored' : 'conflict'
}
