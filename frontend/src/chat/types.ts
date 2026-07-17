export interface ChatContentView {
  version: number
  kind: string
  sentAt: string
  seq: string
  messageId?: string
  body: unknown
  text?: string
}

export interface AccountAddress {
  username: string
  server?: string
}

export type ConversationId =
  | { kind: 'direct'; address: AccountAddress }
  | { kind: 'group'; groupId: string }

export interface ChatHistoryEntry {
  id: string
  conversation: ConversationId
  /** @deprecated Use conversation. */
  peer: string
  direction: 'incoming' | 'outgoing'
  senderDeviceId?: number
  cursor?: string
  timestampMs: number
  delivered: boolean
  deduplicated: boolean
  content: ChatContentView
}

export interface SendSummary {
  delivered: boolean
  deduplicated: boolean
  attempts: number
  safetyNumberChanges: string[]
}

export interface InboundFailure {
  id: string
  kind: string
  error: string
}

export interface ReceiveReport {
  messages: unknown[]
  synced: string[]
  contactSynced: string[]
  profileKeyUpdated: string[]
  profilesRefreshed: string[]
  suppressed: string[]
  undecodable: string[]
  errors: InboundFailure[]
  duplicates: string[]
}

export type ContactState =
  | 'pendingIncoming'
  | 'pendingOutgoing'
  | 'accepted'
  | 'rejected'
  | 'blocked'

export interface ContactRecord {
  peer: string
  state: ContactState
  previousState?: ContactState
  revision: string
  sourceDeviceId: number
  updatedAtMs: number
  syncPending: boolean
}

export interface ChatProfile {
  displayName: string
  avatar?: string
  avatarContentType?: string
  revision: string
}

export interface PeerChatProfile extends ChatProfile {
  peer: string
}

export interface InboundAttention {
  id: string
  cursor: string
  state: string
  attempts: number
  failureKind?: string
  lastError?: string
  receivedAt: number
}

export interface ChatCapabilities {
  enabled: boolean
  protocolVersion: number
  suites: number[]
  maxContentBytes: number
  mailboxRetentionDays: number
  deviceExpiryDays: number
  serverName?: string
  federation: boolean
  manifests: boolean
  profiles: boolean
  keyTransparency: boolean
  transparencyOperatorKeyId?: string
  transparencyOperatorPublicKey?: string
  transparencyWitnesses?: TransparencyVerifierKey[]
  transparencyWitnessQuorum?: number
  sealedSender: boolean
}

export interface TransparencyVerifierKey {
  witnessId: string
  keyId: string
  publicKey: string
}

export interface ChatTransportPort {
  registerDevice(request: unknown): Promise<unknown>
  fetchBundles(username: string, transparencyTreeSize: string): Promise<unknown>
  fetchSyncBundles(
    username: string,
    currentDeviceId: number,
    transparencyTreeSize: string,
  ): Promise<unknown>
  fetchManifest(username: string): Promise<unknown | null>
  publishManifest(manifest: unknown, transparencyTreeSize: string): Promise<unknown>
  fetchOwnProfile(): Promise<unknown | null>
  publishProfile(profile: unknown): Promise<unknown>
  fetchProfile(username: string, version: string, accessKey: string): Promise<unknown | null>
  prekeyCount(deviceId: number): Promise<unknown>
  replenishPrekeys(deviceId: number, request: unknown): Promise<void>
  sendMessage(
    username: string,
    request: unknown,
  ): Promise<
    | { kind: 'delivered'; deduplicated?: boolean }
    | { kind: 'mismatch'; mismatch: unknown }
  >
  sendSyncMessage(
    request: unknown,
  ): Promise<
    | { kind: 'delivered'; deduplicated?: boolean }
    | { kind: 'mismatch'; mismatch: unknown }
  >
  drainMailbox(deviceId: number, after: string | null, limit: number): Promise<unknown>
  ackMessages(deviceId: number, ids: string[]): Promise<void>
}

export interface WasmChatClientHandle {
  readonly deviceId: number
  history(): Promise<ChatHistoryEntry[]>
  contacts(): Promise<ContactRecord[]>
  profile(): Promise<ChatProfile>
  profiles(): Promise<PeerChatProfile[]>
  setProfile(
    displayName: string,
    avatar?: string,
    avatarContentType?: string,
  ): Promise<ChatProfile>
  acceptContact(peer: string): Promise<ContactRecord>
  rejectContact(peer: string): Promise<ContactRecord>
  blockContact(peer: string): Promise<ContactRecord>
  unblockContact(peer: string): Promise<ContactRecord>
  inboundAttention(): Promise<InboundAttention[]>
  maintainPrekeys(): Promise<unknown>
  pendingSendCount(): Promise<number>
  quarantineInbound(id: string): Promise<void>
  reconcile(): Promise<ReceiveReport>
  resolveDeadLetter(id: string): Promise<void>
  sendText(
    sendId: string,
    peer: string,
    sentAt: string,
    text: string,
  ): Promise<SendSummary>
  syncManifest(): Promise<unknown>
  verifyAuthority(peer: string): Promise<unknown>
  free(): void
}

export interface ChatWasmModule {
  default(input?: unknown): Promise<unknown>
  WasmChatClient: {
    open(
      databaseName: string,
      user: string,
      masterKey: Uint8Array,
      transport: ChatTransportPort,
      transparencyPolicy: unknown,
    ): Promise<WasmChatClientHandle>
  }
}
