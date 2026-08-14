import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertTriangle,
  ArrowLeft,
  Ban,
  Bookmark,
  Camera,
  Check,
  CheckCheck,
  Copy,
  Download,
  FileText,
  HardDrive,
  Loader2,
  MessageCircle,
  MessageSquareWarning,
  Mic,
  MonitorSmartphone,
  MoreVertical,
  Plus,
  Paperclip,
  Pencil,
  QrCode,
  RefreshCw,
  Reply,
  Search,
  Send,
  Shield,
  ShieldCheck,
  SmilePlus,
  Square,
  Trash2,
  Timer,
  UserMinus,
  Users,
  X,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { QRCodeSVG } from 'qrcode.react'
import { useIsMobile } from '@/hooks/useIsMobile'
import { useAppSelector } from '@/store'
import { ChatService, ChatServiceError, type ChatMediaStorageView } from '@/chat/service'
import type { ChatBackupView } from '@/chat/backup'
import { MlsSendError } from '@/chat/mls-service'
import { MlsGroupSecurityDetails } from '@/chat/MlsGroupSecurityDetails'
import { SafetyVerificationDialog } from '@/chat/SafetyVerificationDialog'
import { ChatAttachmentPreview } from '@/chat/ChatAttachmentPreview'
import {
  ChatAttachmentAction,
  type ChatAttachmentCacheState,
} from '@/chat/ChatAttachmentAction'
import { ChatAttachmentViewer } from '@/chat/ChatAttachmentViewer'
import { ChatVoiceNotePlayer } from '@/chat/ChatVoiceNotePlayer'
import {
  aggregateLatestReactions,
  CHAT_REACTION_EMOJIS,
  type ChatReactionEmoji,
  type ReactionAggregate,
  type ReactionOperation,
} from '@/chat/reactions'
import { mlsGroupInvitationReadiness } from '@/chat/group-readiness'
import { isSupportedChat, useChatCapabilities } from '@/chat/capabilities'
import { requestLocalChatDeviceReset } from '@/chat/local-store'
import {
  conversationKey,
  canonicalAccountAddress,
  contactUri,
  directAddress,
  directConversation,
  parseAccountAddress,
  withHomeServer,
} from '@/chat/identity'
import type {
  ChatCapabilities,
  ChatDevice,
  ChatHistoryEntry,
  ChatProfile,
  ChatTypingEvent,
  ContactRecord,
  ConversationId,
  InboundAttention,
  LocalMlsConversationRecord,
  MlsAuthorityPolicyInspection,
  MlsConversationMember,
  MlsInvitationFeedback,
  PendingMlsOwnerApprovalRequest,
  PendingMlsInvitation,
  PeerChatProfile,
  SafetyNumberV1,
  ChatMessageMutationV1,
} from '@/chat/types'
import { cn } from '@/lib/utils'
import { copyText } from '@/lib/format'
import {
  clearCachedChatMediaV1,
  chatMediaViewerKindV1,
  downloadChatMediaToCacheV1,
  isChatMediaAvailableInKutupV1,
  saveCachedChatMediaToDeviceV1,
  uploadChatMediaV1,
} from '@/chat/media'
import {
  privateCiphertextCacheForAccountV1,
  type PrivateCiphertextCacheV1,
} from '@/mediaCache'
import {
  disappearingMessageExpiresAt,
  formatRemainingTime,
  isVisibleChatMessage,
  reduceDisappearingTimers,
} from '@/chat/disappearing'
import { searchChatHistory } from '@/chat/search'
import {
  canonicalVoiceNoteMimeType,
  formatVoiceNoteElapsed,
  preferredVoiceNoteMimeType,
  VOICE_NOTE_MAX_DURATION_MS,
  VOICE_NOTE_MAX_PLAINTEXT_BYTES,
  voiceNoteFilename,
} from '@/chat/voice-note'

const DISAPPEARING_PRESETS = [
  { key: 'off', durationSeconds: undefined },
  { key: 'thirtySeconds', durationSeconds: 30 },
  { key: 'oneHour', durationSeconds: 60 * 60 },
  { key: 'oneDay', durationSeconds: 24 * 60 * 60 },
  { key: 'oneWeek', durationSeconds: 7 * 24 * 60 * 60 },
  { key: 'thirtyDays', durationSeconds: 30 * 24 * 60 * 60 },
] as const
interface VoiceRecordingSession {
  recorder: MediaRecorder
  stream: MediaStream
  chunks: Blob[]
  plaintextBytes: number
  startedAt: number
  conversation: ConversationId
  disappearingTimerSeconds?: number
  discard: boolean
}

interface MessageMutationState {
  editedText?: string
  deleted: boolean
}

interface ChatSearchTarget {
  conversationKey: string
  messageId: string
  direction: ChatHistoryEntry['direction']
}

interface MessageReceiptState {
  delivered: number
  read: number
}

export default function Chat() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const capabilities = useChatCapabilities()

  useEffect(() => {
    if (capabilities.data && !isSupportedChat(capabilities.data)) {
      navigate('/drive', { replace: true })
    }
  }, [capabilities.data, navigate])

  if (capabilities.isPending) {
    return (
      <div className="fixed inset-0 flex items-center justify-center bg-background">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <span className="sr-only">{t('chat.checkingSupport')}</span>
      </div>
    )
  }
  if (capabilities.isError) {
    return (
      <div className="fixed inset-0 flex flex-col items-center justify-center gap-4 bg-background p-6 text-center">
        <AlertTriangle className="h-8 w-8 text-destructive" />
        <p className="text-sm text-muted-foreground">{t('chat.errors.capabilities')}</p>
        <Button onClick={() => navigate('/drive', { replace: true })}>
          {t('chat.backToFiles')}
        </Button>
      </div>
    )
  }
  if (!capabilities.data || !isSupportedChat(capabilities.data)) return null

  return <SupportedChat capabilities={capabilities.data} />
}

function SupportedChat({ capabilities }: { capabilities: ChatCapabilities }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const isMobile = useIsMobile()
  const auth = useAppSelector((state) => state.auth)
  const masterKey = useMemo(
    () => (auth.masterKey ? new Uint8Array(auth.masterKey) : null),
    [auth.masterKey],
  )
  const mediaCache = useMemo(
    () => auth.userId ? privateCiphertextCacheForAccountV1(auth.userId) : null,
    [auth.userId],
  )
  const [service, setService] = useState<ChatService | null>(null)
  const [history, setHistory] = useState<ChatHistoryEntry[]>([])
  const [contacts, setContacts] = useState<ContactRecord[]>([])
  const [attention, setAttention] = useState<InboundAttention[]>([])
  const [localProfile, setLocalProfile] = useState<ChatProfile | null>(null)
  const [peerProfiles, setPeerProfiles] = useState<PeerChatProfile[]>([])
  const [groups, setGroups] = useState<LocalMlsConversationRecord[]>([])
  const [groupInvitations, setGroupInvitations] = useState<PendingMlsInvitation[]>([])
  const [groupInvitationFeedback, setGroupInvitationFeedback] =
    useState<MlsInvitationFeedback[]>([])
  const [ownerApprovalRequests, setOwnerApprovalRequests] =
    useState<PendingMlsOwnerApprovalRequest[]>([])
  const [selectedConversation, setSelectedConversation] = useState<ConversationId | null>(null)
  const [newPeer, setNewPeer] = useState('')
  const [searchOpen, setSearchOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [searchTarget, setSearchTarget] = useState<ChatSearchTarget | null>(null)
  const [highlightedSearchMessage, setHighlightedSearchMessage] = useState<string | null>(null)
  const [draft, setDraft] = useState('')
  const [replyingTo, setReplyingTo] = useState<ChatHistoryEntry | null>(null)
  const [editingMessage, setEditingMessage] = useState<ChatHistoryEntry | null>(null)
  const [loading, setLoading] = useState(true)
  const [sending, setSending] = useState(false)
  const [reactionSending, setReactionSending] = useState<string | null>(null)
  const [mutationSending, setMutationSending] = useState(false)
  const [timerSending, setTimerSending] = useState(false)
  const [nowMs, setNowMs] = useState(() => Date.now())
  const [readReceiptsEnabled, setReadReceiptsEnabled] = useState(() =>
    window.localStorage.getItem('kutup:chat:read-receipts') === '1')
  const [pageVisible, setPageVisible] = useState(() => document.visibilityState === 'visible')
  const [typingByConversation, setTypingByConversation] = useState(
    () => new Map<string, Map<string, number>>(),
  )
  const [contactUpdating, setContactUpdating] = useState(false)
  const [groupUpdating, setGroupUpdating] = useState(false)
  const [newGroupOpen, setNewGroupOpen] = useState(false)
  const [newGroupMember, setNewGroupMember] = useState('')
  const [addGroupMemberOpen, setAddGroupMemberOpen] = useState(false)
  const [groupMembersOpen, setGroupMembersOpen] = useState(false)
  const [groupMember, setGroupMember] = useState('')
  const [groupAuthorityDomains, setGroupAuthorityDomains] = useState('')
  const [groupAuthorityPolicies, setGroupAuthorityPolicies] =
    useState<MlsAuthorityPolicyInspection[]>([])
  const [groupAuthorityPoliciesLoading, setGroupAuthorityPoliciesLoading] = useState(false)
  const [groupMaximumPlaintext, setGroupMaximumPlaintext] = useState('')
  const [selectedSafety, setSelectedSafety] = useState<SafetyNumberV1 | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [deviceResetOpen, setDeviceResetOpen] = useState(false)
  const [deviceResetting, setDeviceResetting] = useState(false)
  const [devicesOpen, setDevicesOpen] = useState(false)
  const [devices, setDevices] = useState<ChatDevice[]>([])
  const [devicesLoading, setDevicesLoading] = useState(false)
  const [deviceRevoking, setDeviceRevoking] = useState<number | null>(null)
  const [backupStatus, setBackupStatus] = useState<ChatBackupView | null>(null)
  const [mediaStorageOpen, setMediaStorageOpen] = useState(false)
  const [mediaStorage, setMediaStorage] = useState<ChatMediaStorageView | null>(null)
  const [mediaStorageLoading, setMediaStorageLoading] = useState(false)
  const [mediaStorageClearing, setMediaStorageClearing] = useState<string | null>(null)
  const [voiceStarting, setVoiceStarting] = useState(false)
  const [voiceRecording, setVoiceRecording] = useState(false)
  const [voiceStopping, setVoiceStopping] = useState(false)
  const [voiceElapsedMs, setVoiceElapsedMs] = useState(0)
  const endRef = useRef<HTMLDivElement>(null)
  const attachmentInputRef = useRef<HTMLInputElement>(null)
  const captureInputRef = useRef<HTMLInputElement>(null)
  const voiceRecordingRef = useRef<VoiceRecordingSession | null>(null)
  const voiceTimerRef = useRef<number | null>(null)
  const voiceMountedRef = useRef(true)
  const voiceStartingRef = useRef(false)
  const selectedConversationKeyRef = useRef<string | null>(null)
  const historyRefreshGeneration = useRef(0)
  const receiptAttempted = useRef(new Set<string>())
  const typingSentAt = useRef(new Map<string, number>())
  const expiryRefreshPending = useRef(false)
  const expiryStartAttempted = useRef(new Set<string>())
  const selfAccount = useMemo(
    () =>
      auth.username
        ? withHomeServer({ username: auth.username }, capabilities.serverName)
        : null,
    [auth.username, capabilities.serverName],
  )
  const selfAddress = selfAccount
    ? directAddress(directConversation(selfAccount))
    : null

  useEffect(() => {
    if (!mediaCache) return
    void mediaCache.initialize().catch(cause => {
      console.warn('Private media cache could not be initialized', cause)
    })
  }, [mediaCache])

  useEffect(() => {
    voiceMountedRef.current = true
    return () => {
      voiceMountedRef.current = false
      voiceStartingRef.current = false
      const session = voiceRecordingRef.current
      if (session) {
        session.discard = true
        if (session.recorder.state !== 'inactive') session.recorder.stop()
        session.stream.getTracks().forEach(track => track.stop())
        voiceRecordingRef.current = null
      }
      if (voiceTimerRef.current !== null) window.clearInterval(voiceTimerRef.current)
    }
  }, [])

  useEffect(() => {
    if (!auth.userId || !auth.username || !masterKey) {
      setError(t('chat.errors.sessionMissing'))
      setLoading(false)
      return
    }

    let cancelled = false
    let opened: ChatService | null = null
    const refresh = async () => {
      if (!opened || cancelled) return
      const generation = ++historyRefreshGeneration.current
      try {
        const [nextHistory, nextAttention, nextContacts, nextProfile, nextProfiles, nextGroups, nextInvitations, nextInvitationFeedback, nextOwnerApprovals] = await Promise.all([
          opened.history(),
          opened.inboundAttention(),
          opened.contacts(),
          opened.profile(),
          opened.profiles(),
          capabilities.mlsGroups ? opened.groups() : Promise.resolve([]),
          capabilities.mlsGroups ? opened.groupInvitations() : Promise.resolve([]),
          capabilities.mlsGroups ? opened.groupInvitationFeedback() : Promise.resolve([]),
          capabilities.mlsGroups ? opened.pendingGroupOwnerApprovals() : Promise.resolve([]),
        ])
        if (!cancelled) {
          if (generation === historyRefreshGeneration.current) setHistory(nextHistory)
          setAttention(nextAttention)
          setContacts(nextContacts)
          setLocalProfile(nextProfile)
          setPeerProfiles(nextProfiles)
          setGroups(nextGroups)
          setGroupInvitations(nextInvitations)
          setGroupInvitationFeedback(nextInvitationFeedback)
          setOwnerApprovalRequests(nextOwnerApprovals)
          setBackupStatus(opened.backupStatus())
          setError(null)
        }
      } catch (cause) {
        if (!cancelled) setError(errorMessage(cause, t))
      }
    }

    ChatService.open({
      userId: auth.userId,
      email: auth.email!,
      username: auth.username,
      masterKey,
      capabilities,
    })
      .then(async (next) => {
        if (cancelled) {
          next.dispose()
          return
        }
        opened = next
        setService(next)
        next.subscribe(() => void refresh())
        if (mediaCache) {
          next.subscribeAttachmentExpiry(async attachmentIds => {
            await Promise.all(attachmentIds.map(
              attachmentId => mediaCache.removeObject('chat', attachmentId),
            ))
          })
        }
        next.subscribeTyping((event: ChatTypingEvent) => {
          const key = conversationKey(event.conversation)
          setTypingByConversation((current) => {
            const nextState = new Map(current)
            const senders = new Map(nextState.get(key) ?? [])
            if (event.active) senders.set(event.sender, Date.now() + 6_000)
            else senders.delete(event.sender)
            if (senders.size > 0) nextState.set(key, senders)
            else nextState.delete(key)
            return nextState
          })
        })
        await refresh()
      })
      .catch((cause) => {
        if (!cancelled) {
          console.error('Secure chat failed to initialize', cause)
          setError(errorMessage(cause, t))
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
      opened?.dispose()
    }
  }, [auth.userId, auth.username, capabilities, masterKey, mediaCache, t])

  const contactsByPeer = useMemo(
    () => new Map(contacts.map((contact) => [contact.peer, contact])),
    [contacts],
  )
  const profilesByPeer = useMemo(
    () => new Map(peerProfiles.map((profile) => [profile.peer, profile])),
    [peerProfiles],
  )

  const activeTimersByConversation = useMemo(
    () => reduceDisappearingTimers(history),
    [history],
  )

  const visibleHistory = useMemo(
    () => history.filter(message => isVisibleChatMessage(message, nowMs)),
    [history, nowMs],
  )

  const peers = useMemo(() => {
    const latest = new Map<string, { conversation: ConversationId; message: ChatHistoryEntry }>()
    for (const message of visibleHistory) {
      latest.set(conversationKey(message.conversation), {
        conversation: message.conversation,
        message,
      })
    }
    return Array.from(latest.values())
      .filter(({ conversation }) => conversation.kind === 'direct')
      .filter(({ conversation }) => directAddress(conversation) !== selfAddress)
      .filter(({ conversation }) => {
        const address = directAddress(conversation)
        const state = address ? contactsByPeer.get(address)?.state : undefined
        return state !== 'pendingIncoming' && state !== 'rejected'
      })
      .sort((left, right) => right.message.timestampMs - left.message.timestampMs)
  }, [contactsByPeer, selfAddress, visibleHistory])

  const restoredHistoryGroups = useMemo(() => {
    const liveGroupIds = new Set(groups.map(
      group => group.request.genesis.conversationId,
    ))
    const latest = new Map<string, ChatHistoryEntry>()
    for (const message of visibleHistory) {
      if (message.conversation.kind !== 'group'
          || liveGroupIds.has(message.conversation.groupId)) continue
      latest.set(message.conversation.groupId, message)
    }
    return Array.from(latest, ([groupId, message]) => ({ groupId, message }))
      .sort((left, right) => right.message.timestampMs - left.message.timestampMs)
  }, [groups, visibleHistory])

  const requests = useMemo(
    () =>
      contacts
        .filter((contact) => contact.state === 'pendingIncoming')
        .flatMap((contact) => {
          const address = parseAccountAddress(contact.peer)
          return address
            ? [{
                contact,
                conversation: directConversation(address),
                message: visibleHistory
                  .filter((message) => directAddress(message.conversation) === contact.peer)
                  .at(-1),
              }]
            : []
        })
        .sort((left, right) => right.contact.updatedAtMs - left.contact.updatedAtMs),
    [contacts, visibleHistory],
  )

  useEffect(() => {
    if (!selectedConversation && peers[0]) setSelectedConversation(peers[0].conversation)
    else if (!selectedConversation && groups[0]) {
      setSelectedConversation({
        kind: 'group',
        groupId: groups[0].request.genesis.conversationId,
      })
    } else if (!selectedConversation && restoredHistoryGroups[0]) {
      setSelectedConversation({
        kind: 'group',
        groupId: restoredHistoryGroups[0].groupId,
      })
    }
  }, [groups, peers, restoredHistoryGroups, selectedConversation])

  const selectedKey = selectedConversation ? conversationKey(selectedConversation) : null
  useEffect(() => {
    selectedConversationKeyRef.current = selectedKey
    const session = voiceRecordingRef.current
    if (session && conversationKey(session.conversation) !== selectedKey) {
      stopVoiceRecording(true)
    }
  }, [selectedKey])
  const selectedTimerSeconds = selectedKey
    ? activeTimersByConversation.get(selectedKey)?.durationSeconds
    : undefined
  const selectedAddress = selectedConversation ? directAddress(selectedConversation) : null
  const selectedGroup = selectedConversation?.kind === 'group'
    ? groups.find(group =>
        group.request.genesis.conversationId === selectedConversation.groupId)
    : undefined
  const selectedRestoredHistoryGroup = selectedConversation?.kind === 'group'
    && selectedGroup === undefined
    && restoredHistoryGroups.some(group => group.groupId === selectedConversation.groupId)
  const selectedGroupSelfMember = selectedGroup?.currentRoster.find(member =>
    canonicalAccountAddress(member.address) === selfAddress)
  const selectedGroupClosed = selectedGroup?.status === 'closed'
  const canManageSelectedGroup = selectedGroupSelfMember?.isAdmin === true && !selectedGroupClosed
  const selectedGroupInvitationFeedback = selectedGroup
    ? groupInvitationFeedback.filter(feedback =>
        feedback.conversationId === selectedGroup.request.genesis.conversationId
        && feedback.incarnation === selectedGroup.request.genesis.incarnation
        && feedback.member.server
        && selectedGroup.currentRoster.some(member =>
          canonicalAccountAddress(member.address) === canonicalAccountAddress(feedback.member)))
    : []
  const canManageSelectedGroupAuthorities = Boolean(selectedGroupSelfMember?.ownerId) && !selectedGroupClosed
  const selectedOwnerApproval = selectedGroup
    ? ownerApprovalRequests.find(request =>
        request.request.proposal.conversationId
          === selectedGroup.request.genesis.conversationId)
    : undefined
  const selectedGroupAdministratorCount = selectedGroup?.currentRoster.filter(
    member => member.isAdmin,
  ).length ?? 0
  const selectedGroupCanSend = !selectedGroup
    || selectedGroup.currentAuthorizationPolicy.applicationSenders === 1
    || selectedGroupSelfMember?.isAdmin === true
  const selectedGroupReadiness = useMemo(
    () => selectedGroup
      ? mlsGroupInvitationReadiness(
          selectedGroup,
          groupInvitationFeedback,
          selfAddress,
        )
      : { pending: [], refused: [], blocksSending: false },
    [groupInvitationFeedback, selectedGroup, selfAddress],
  )

  useEffect(() => {
    setGroupAuthorityDomains(
      selectedGroup?.currentAuthoritySet.authorities
        .map(authority => authority.domain)
        .join(', ') ?? '',
    )
  }, [selectedGroup?.request.genesis.conversationId, selectedGroup?.currentAuthoritySet.sequence])
  useEffect(() => {
    setGroupMaximumPlaintext(
      selectedGroup?.currentCryptographicPolicy.maximumApplicationPlaintextBytes.toString() ?? '',
    )
  }, [
    selectedGroup?.request.genesis.conversationId,
    selectedGroup?.currentCryptographicPolicy.sequence,
  ])
  useEffect(() => {
    if (!groupMembersOpen || !service || !selectedGroup) {
      setGroupAuthorityPolicies([])
      setGroupAuthorityPoliciesLoading(false)
      return
    }
    let cancelled = false
    setGroupAuthorityPolicies([])
    setGroupAuthorityPoliciesLoading(true)
    void service
      .groupAuthorityPolicyDetails(selectedGroup.request.genesis.conversationId)
      .then(policies => {
        if (!cancelled) setGroupAuthorityPolicies(policies)
      })
      .catch(() => {
        if (!cancelled) setGroupAuthorityPolicies([])
      })
      .finally(() => {
        if (!cancelled) setGroupAuthorityPoliciesLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [
    groupMembersOpen,
    selectedGroup?.request.genesis.conversationId,
    selectedGroup?.currentAuthoritySet.sequence,
    service,
  ])
  const selectedLabel = selectedAddress ??
    (selectedConversation?.kind === 'group'
      ? `Group ${selectedConversation.groupId.slice(0, 8)}`
      : '')
  const noteSelected = selectedAddress === selfAddress
  const selectedProfile = selectedAddress && !noteSelected
    ? profilesByPeer.get(selectedAddress)
    : undefined
  const selectedTitle = noteSelected
    ? t('chat.noteToSelf')
    : selectedProfile?.displayName || selectedLabel || t('chat.selectConversation')
  const selectedContact = selectedAddress ? contactsByPeer.get(selectedAddress) : undefined
  const requestSelected = selectedContact?.state === 'pendingIncoming'
  const blockedSelected = selectedContact?.state === 'blocked'
  const canSend = Boolean(
    selectedConversation
      && !requestSelected
      && !blockedSelected
      && !selectedRestoredHistoryGroup
      && !selectedGroupClosed
      && selectedGroupCanSend
      && !selectedGroupReadiness.blocksSending,
  )
  const canSendMedia = canSend && Boolean(
    selectedConversation?.kind === 'group'
      || noteSelected
      || selectedContact?.state === 'accepted',
  )
  const canSetDisappearingTimer = canSend && Boolean(
    selectedConversation?.kind === 'group'
      || noteSelected
      || selectedContact?.state === 'accepted',
  )
  const canSendTyping = canSend && Boolean(
    selectedConversation?.kind === 'group'
      || selectedContact?.state === 'accepted'
      || selectedContact?.state === 'pendingOutgoing',
  )
  const draftWithinTypingLimit = selectedConversation?.kind !== 'group'
    || Boolean(
      selectedGroup
      && new TextEncoder().encode(draft.trim()).byteLength
        <= selectedGroup.currentCryptographicPolicy.maximumApplicationPlaintextBytes,
    )

  useEffect(() => {
    const timer = window.setInterval(() => {
      const now = Date.now()
      setNowMs(now)
      setTypingByConversation((current) => {
        let changed = false
        const nextState = new Map<string, Map<string, number>>()
        for (const [key, senders] of current) {
          const active = new Map(Array.from(senders).filter(([, expiresAt]) => expiresAt > now))
          if (active.size !== senders.size) changed = true
          if (active.size > 0) nextState.set(key, active)
        }
        return changed ? nextState : current
      })
    }, 1_000)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    if (!service || expiryRefreshPending.current) return
    const elapsed = history.some(message => {
      const expiresAt = disappearingMessageExpiresAt(message)
      return expiresAt !== undefined && nowMs >= expiresAt
    })
    if (!elapsed) return
    expiryRefreshPending.current = true
    void service.history()
      .then(setHistory)
      .catch(cause => console.warn('Expired Chat history could not be purged', cause))
      .finally(() => { expiryRefreshPending.current = false })
  }, [history, nowMs, service])

  useEffect(() => {
    if (
      !service
      || !selectedConversation
      || !selectedKey
      || noteSelected
      || !canSendTyping
      || !draftWithinTypingLimit
      || !pageVisible
      || !draft.trim()
    ) return
    const now = Date.now()
    if (now - (typingSentAt.current.get(selectedKey) ?? 0) < 4_000) return
    typingSentAt.current.set(selectedKey, now)
    void service.sendTyping(selectedConversation, true).catch(cause => {
      console.warn('Encrypted Chat typing indicator could not be sent', cause)
    })
  }, [
    canSendTyping,
    draft,
    draftWithinTypingLimit,
    noteSelected,
    pageVisible,
    selectedConversation,
    selectedKey,
    service,
  ])

  const messages = useMemo(
    () =>
      selectedKey
        ? visibleHistory.filter((message) => conversationKey(message.conversation) === selectedKey)
        : [],
    [selectedKey, visibleHistory],
  )
  const activeTypingSenders = selectedKey
    ? Array.from(typingByConversation.get(selectedKey)?.keys() ?? [])
      .filter(sender => sender !== selfAddress)
    : []
  const typingLabel = activeTypingSenders.length === 1
    ? t('chat.typing.one', {
        name: profilesByPeer.get(activeTypingSenders[0])?.displayName
          || activeTypingSenders[0].split('@')[0],
      })
    : activeTypingSenders.length > 1
      ? t('chat.typing.many', { count: activeTypingSenders.length })
      : null
  const messagesById = useMemo(
    () => new Map(messages.map(message => [message.content.messageId ?? message.id, message])),
    [messages],
  )
  const reactionsByMessageId = useMemo(() => {
    if (!selectedKey || !selectedConversation || !selfAddress) {
      return new Map<string, ReactionAggregate[]>()
    }
    const targetIds = new Set(messages.flatMap(message =>
      message.content.messageId ? [message.content.messageId] : []))
    const operations: ReactionOperation[] = []
    for (const message of history) {
      const reaction = message.content.reaction
      if (!reaction
          || conversationKey(message.conversation) !== selectedKey
          || !targetIds.has(reaction.targetMessageId)) continue
      const reactor = message.direction === 'outgoing'
        ? selfAddress
        : selectedConversation.kind === 'direct'
          ? directAddress(selectedConversation)
          : message.peer
      if (!reactor) continue
      operations.push({ message, reaction, reactor })
    }
    return aggregateLatestReactions(operations, targetIds, selfAddress)
  }, [history, messages, selectedConversation, selectedKey, selfAddress])
  const mutationsByMessageId = useMemo(() => {
    if (!selfAddress) {
      return new Map<string, MessageMutationState>()
    }
    const targets = new Map(visibleHistory.flatMap(message =>
      message.content.messageId ? [[message.content.messageId, message] as const] : []))
    const edits = new Map<string, { message: ChatHistoryEntry; mutation: ChatMessageMutationV1 }>()
    const deleted = new Set<string>()
    for (const message of history) {
      const mutation = message.content.mutation
      if (!mutation) continue
      const target = targets.get(mutation.targetMessageId)
      if (!target
          || conversationKey(message.conversation) !== conversationKey(target.conversation)) continue
      const actor = messageActor(message, message.conversation, selfAddress)
      const targetAuthor = messageActor(target, target.conversation, selfAddress)
      if (!actor || actor !== targetAuthor) continue
      if (mutation.operation === 'delete') {
        deleted.add(mutation.targetMessageId)
        continue
      }
      const previous = edits.get(mutation.targetMessageId)
      if (!previous || compareContentOperations(previous.message, message) < 0) {
        edits.set(mutation.targetMessageId, { message, mutation })
      }
    }
    const result = new Map<string, MessageMutationState>()
    for (const targetMessageId of targets.keys()) {
      const edit = edits.get(targetMessageId)?.mutation.replacementText
      if (edit !== undefined || deleted.has(targetMessageId)) {
        result.set(targetMessageId, {
          editedText: edit,
          deleted: deleted.has(targetMessageId),
        })
      }
    }
    return result
  }, [history, selfAddress, visibleHistory])
  const searchResults = useMemo(
    () => searchChatHistory(visibleHistory, searchQuery, mutationsByMessageId),
    [mutationsByMessageId, searchQuery, visibleHistory],
  )
  const ownReceiptStateByMessageId = useMemo(() => {
    const states = new Map<string, 'delivered' | 'read'>()
    for (const message of history) {
      const receipt = message.content.receipt
      if (!receipt || message.direction !== 'outgoing') continue
      for (const messageId of receipt.messageIds) {
        if (receipt.state === 'read' || !states.has(messageId)) {
          states.set(messageId, receipt.state)
        }
      }
    }
    return states
  }, [history])
  const receiptsByMessageId = useMemo(() => {
    if (!selfAddress) return new Map<string, MessageReceiptState>()
    const targets = new Map(visibleHistory.flatMap(message =>
      message.direction === 'outgoing' && message.content.messageId
        ? [[message.content.messageId, message] as const]
        : []))
    const states = new Map<string, 'delivered' | 'read'>()
    for (const message of history) {
      const receipt = message.content.receipt
      if (!receipt || message.direction !== 'incoming') continue
      const actor = messageActor(message, message.conversation, selfAddress)
      if (!actor || actor === selfAddress) continue
      for (const messageId of receipt.messageIds) {
        const target = targets.get(messageId)
        if (!target
            || conversationKey(target.conversation) !== conversationKey(message.conversation)) continue
        const key = `${messageId}\u0000${actor}`
        if (receipt.state === 'read' || !states.has(key)) states.set(key, receipt.state)
      }
    }
    const result = new Map<string, MessageReceiptState>()
    for (const [key, state] of states) {
      const messageId = key.slice(0, key.indexOf('\u0000'))
      const current = result.get(messageId) ?? { delivered: 0, read: 0 }
      current.delivered += 1
      if (state === 'read') current.read += 1
      result.set(messageId, current)
    }
    return result
  }, [history, selfAddress, visibleHistory])

  useEffect(() => {
    const update = () => setPageVisible(document.visibilityState === 'visible')
    document.addEventListener('visibilitychange', update)
    return () => document.removeEventListener('visibilitychange', update)
  }, [])

  useEffect(() => {
    if (!service || loading || !selfAddress) return
    const batches = new Map<string, {
      conversation: ConversationId
      state: 'delivered' | 'read'
      messageIds: string[]
    }>()
    for (const message of visibleHistory) {
      const messageId = message.content.messageId
      if (message.direction !== 'incoming' || !messageId) continue
      if (message.conversation.kind === 'direct') {
        const peer = directAddress(message.conversation)
        if (!peer) continue
        const contact = contactsByPeer.get(peer)
        if (peer !== selfAddress
            && contact?.state !== 'accepted'
            && contact?.state !== 'pendingOutgoing') continue
      }
      if (message.conversation.kind === 'group') {
        const groupId = message.conversation.groupId
        if (!groups.some(group =>
          group.status === 'active'
          && group.request.genesis.conversationId === groupId)) continue
      }
      const shouldMarkRead = readReceiptsEnabled
        && pageVisible
        && selectedKey === conversationKey(message.conversation)
      // An MLS receipt consumes a claimed one-time KeyPackage for every
      // recipient device. Automatic group delivery receipts would double the
      // package and anonymous-request rate of an active group, so groups emit
      // only the explicitly enabled read state. Direct delivery remains
      // automatic because it rides the existing Signal session.
      if (message.conversation.kind === 'group' && !shouldMarkRead) continue
      const state = shouldMarkRead ? 'read' : 'delivered'
      const existing = ownReceiptStateByMessageId.get(messageId)
      if (existing === 'read' || existing === state) continue
      const flightKey = `${state}:${messageId}`
      if (receiptAttempted.current.has(flightKey)) continue
      const key = `${conversationKey(message.conversation)}\u0000${state}`
      const batch = batches.get(key) ?? {
        conversation: message.conversation,
        state,
        messageIds: [],
      }
      batch.messageIds.push(messageId)
      batches.set(key, batch)
      // Once the crypto engine accepts a receipt it owns an exact durable
      // outbox entry. Re-creating the logical receipt after a transport error
      // would consume a new MLS generation and can amplify rate limiting.
      receiptAttempted.current.add(flightKey)
    }
    if (batches.size === 0) return
    let cancelled = false
    void (async () => {
      let sent = false
      for (const batch of batches.values()) {
        for (let offset = 0; offset < batch.messageIds.length; offset += 64) {
          const messageIds = batch.messageIds.slice(offset, offset + 64)
          try {
            await service.sendReceipt(batch.conversation, messageIds, batch.state)
            sent = true
          } catch (cause) {
            console.warn('Encrypted Chat receipt could not be sent', cause)
          }
        }
      }
      if (sent && !cancelled) setHistory(await service.history())
    })()
    return () => { cancelled = true }
  }, [
    contactsByPeer,
    groups,
    loading,
    ownReceiptStateByMessageId,
    pageVisible,
    readReceiptsEnabled,
    selectedKey,
    selfAddress,
    service,
    visibleHistory,
  ])

  useEffect(() => {
    setReplyingTo(null)
    setEditingMessage(null)
  }, [selectedKey])

  useEffect(() => {
    if (!service || !selectedAddress || noteSelected) {
      setSelectedSafety(null)
      return
    }
    let cancelled = false
    setSelectedSafety(null)
    void service
      .safetyNumber(selectedAddress)
      .then(safety => {
        if (!cancelled) setSelectedSafety(safety)
      })
      .catch(() => {
        if (!cancelled) setSelectedSafety(null)
      })
    return () => {
      cancelled = true
    }
  }, [contacts.length, history.length, noteSelected, selectedAddress, service])

  useEffect(() => {
    if (!devicesOpen || !service) return
    let cancelled = false
    setDevicesLoading(true)
    const load = (showError: boolean) => {
      void service.devices()
        .then((nextDevices) => {
          if (!cancelled) {
            setDevices(nextDevices)
            setBackupStatus(service.backupStatus())
          }
        })
        .catch(cause => {
          if (!cancelled && showError) toast.error(errorMessage(cause, t))
        })
        .finally(() => {
          if (!cancelled) setDevicesLoading(false)
        })
    }
    load(true)
    const polling = window.setInterval(() => load(false), 3_000)
    return () => {
      cancelled = true
      window.clearInterval(polling)
    }
  }, [devicesOpen, service, t])

  useEffect(() => {
    if (!mediaStorageOpen || !service || !capabilities.media) return
    let cancelled = false
    setMediaStorageLoading(true)
    void service.chatMediaStorage()
      .then(storage => {
        if (!cancelled) setMediaStorage(storage)
      })
      .catch(cause => {
        if (!cancelled) toast.error(errorMessage(cause, t))
      })
      .finally(() => {
        if (!cancelled) setMediaStorageLoading(false)
      })
    return () => { cancelled = true }
  }, [capabilities.media, mediaStorageOpen, service, t])

  async function revokeChatDevice(device: ChatDevice) {
    if (!service || device.deviceId === service.deviceId || !window.confirm(
      t('chat.devices.confirm', { device: device.name || `Device ${device.deviceId}` }),
    )) return
    setDeviceRevoking(device.deviceId)
    try {
      setDevices(await service.revokeDevice(device.deviceId))
      toast.success(t('chat.devices.revoked'))
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setDeviceRevoking(null)
    }
  }

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' })
  }, [messages.length, selectedKey])

  useEffect(() => {
    if (!searchTarget || searchTarget.conversationKey !== selectedKey) return
    const frame = window.requestAnimationFrame(() => {
      const key = chatMessageDomKey(searchTarget.direction, searchTarget.messageId)
      const element = document.getElementById(key)
      setSearchTarget(null)
      if (!element) return
      element.scrollIntoView({ behavior: 'smooth', block: 'center' })
      setHighlightedSearchMessage(key)
    })
    return () => window.cancelAnimationFrame(frame)
  }, [messages, searchTarget, selectedKey])

  useEffect(() => {
    if (!highlightedSearchMessage) return
    const timeout = window.setTimeout(() => setHighlightedSearchMessage(null), 2_500)
    return () => window.clearTimeout(timeout)
  }, [highlightedSearchMessage])

  function openSearchResult(message: ChatHistoryEntry) {
    setSearchTarget({
      conversationKey: conversationKey(message.conversation),
      messageId: message.id,
      direction: message.direction,
    })
    setSelectedConversation(message.conversation)
    setSearchOpen(false)
  }

  function startConversation(event: FormEvent) {
    event.preventDefault()
    const parsed = parseAccountAddress(newPeer)
    const address = parsed ? withHomeServer(parsed, capabilities.serverName) : null
    if (!address) {
      toast.error(t('chat.errors.invalidAddress'))
      return
    }
    setSelectedConversation(directConversation(address))
    setNewPeer('')
  }

  async function sendMessage(event: FormEvent) {
    event.preventDefault()
    const text = draft.trim()
    if (!service || !selectedConversation || !text || sending || mutationSending) return
    if (editingMessage?.content.messageId) {
      setMutationSending(true)
      try {
        const summary = await service.mutateMessage(
          selectedConversation,
          editingMessage.content.messageId,
          'edit',
          text,
        )
        if (summary.safetyNumberChanges.length > 0) {
          toast.warning(t('chat.safetyNumberChanged'))
        }
        setHistory(await service.history())
        setDraft('')
        setEditingMessage(null)
      } catch (cause) {
        toast.error(errorMessage(cause, t))
      } finally {
        setMutationSending(false)
      }
      return
    }
    setSending(true)
    setDraft('')
    try {
      const summary = await service.send(
        selectedConversation,
        text,
        replyingTo?.content.messageId,
        selectedTimerSeconds,
      )
      if (summary.safetyNumberChanges.length > 0) {
        toast.warning(t('chat.safetyNumberChanged'))
      }
      setHistory(await service.history())
      setReplyingTo(null)
    } catch (cause) {
      setDraft(text)
      toast.error(errorMessage(cause, t))
    } finally {
      setSending(false)
    }
  }

  function beginEditing(message: ChatHistoryEntry) {
    const messageId = message.content.messageId
    const text = messageId
      ? mutationsByMessageId.get(messageId)?.editedText ?? message.content.text
      : message.content.text
    if (!text) return
    setReplyingTo(null)
    setEditingMessage(message)
    setDraft(text)
  }

  async function deleteMessage(message: ChatHistoryEntry) {
    const targetMessageId = message.content.messageId
    if (!service || !selectedConversation || !targetMessageId || mutationSending
        || !window.confirm(t('chat.mutations.confirmDelete'))) return
    setMutationSending(true)
    try {
      const summary = await service.mutateMessage(
        selectedConversation,
        targetMessageId,
        'delete',
      )
      if (summary.safetyNumberChanges.length > 0) {
        toast.warning(t('chat.safetyNumberChanged'))
      }
      setHistory(await service.history())
      if (editingMessage?.content.messageId === targetMessageId) {
        setEditingMessage(null)
        setDraft('')
      }
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setMutationSending(false)
    }
  }

  async function toggleReaction(
    message: ChatHistoryEntry,
    emoji: ChatReactionEmoji,
    active: boolean,
  ) {
    const targetMessageId = message.content.messageId
    if (!service || !selectedConversation || !targetMessageId || reactionSending) return
    const operation = `${targetMessageId}:${emoji}`
    setReactionSending(operation)
    try {
      const summary = await service.sendReaction(
        selectedConversation,
        targetMessageId,
        emoji,
        active,
      )
      if (summary.safetyNumberChanges.length > 0) {
        toast.warning(t('chat.safetyNumberChanged'))
      }
      setHistory(await service.history())
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setReactionSending(null)
    }
  }

  async function sendAttachmentFile(
    file: File,
    mediaOptions: { durationMs?: number } = {},
    target?: { conversation: ConversationId; disappearingTimerSeconds?: number },
  ) {
    const conversation = target?.conversation ?? selectedConversation
    const disappearingTimerSeconds = target
      ? target.disappearingTimerSeconds
      : selectedTimerSeconds
    if (!service || !conversation || !auth.accessToken || sending ||
        !capabilities.media || !capabilities.serverName) return
    if (file.size > capabilities.media.maximumPlaintextBytes) {
      toast.error(`Attachment exceeds this server's ${formatBytes(capabilities.media.maximumPlaintextBytes)} limit`)
      return
    }
    setSending(true)
    try {
      const uploaded = await uploadChatMediaV1({
        file,
        originDomain: capabilities.serverName,
        accessToken: auth.accessToken,
        ...mediaOptions,
      })
      const summary = await service.sendAttachment(
        conversation,
        uploaded.descriptor,
        uploaded.storageReferenceId,
        disappearingTimerSeconds,
      )
      if (summary.safetyNumberChanges.length > 0) {
        toast.warning(t('chat.safetyNumberChanged'))
      }
      setHistory(await service.history())
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setSending(false)
      if (attachmentInputRef.current) attachmentInputRef.current.value = ''
      if (captureInputRef.current) captureInputRef.current.value = ''
    }
  }

  function releaseVoiceRecording(session: VoiceRecordingSession) {
    session.stream.getTracks().forEach(track => track.stop())
    if (voiceRecordingRef.current === session) voiceRecordingRef.current = null
    if (voiceTimerRef.current !== null) {
      window.clearInterval(voiceTimerRef.current)
      voiceTimerRef.current = null
    }
    if (voiceMountedRef.current) {
      setVoiceRecording(false)
      setVoiceElapsedMs(0)
    }
  }

  function stopVoiceRecording(discard: boolean) {
    const session = voiceRecordingRef.current
    if (!session) return
    session.discard = discard
    if (!discard) setVoiceStopping(true)
    if (session.recorder.state !== 'inactive') {
      session.recorder.stop()
    } else {
      releaseVoiceRecording(session)
      if (voiceMountedRef.current) setVoiceStopping(false)
    }
  }

  async function startVoiceRecording() {
    if (!service || !selectedConversation || !canSendMedia || sending ||
        voiceStartingRef.current || voiceRecording || voiceStopping || !capabilities.media) return
    if (typeof MediaRecorder === 'undefined' || !navigator.mediaDevices?.getUserMedia) {
      toast.error(t('chat.voice.unsupported'))
      return
    }
    const conversation = selectedConversation
    const targetConversationKey = conversationKey(conversation)
    const disappearingTimerSeconds = selectedTimerSeconds
    voiceStartingRef.current = true
    setVoiceStarting(true)
    let stream: MediaStream | null = null
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true,
        },
        video: false,
      })
      if (!voiceMountedRef.current || selectedConversationKeyRef.current !== targetConversationKey) {
        stream.getTracks().forEach(track => track.stop())
        return
      }
      const preferredMimeType = preferredVoiceNoteMimeType(
        mimeType => MediaRecorder.isTypeSupported(mimeType),
      )
      const recorder = new MediaRecorder(
        stream,
        preferredMimeType ? { mimeType: preferredMimeType } : undefined,
      )
      const session: VoiceRecordingSession = {
        recorder,
        stream,
        chunks: [],
        plaintextBytes: 0,
        startedAt: Date.now(),
        conversation,
        disappearingTimerSeconds,
        discard: false,
      }
      voiceRecordingRef.current = session
      recorder.ondataavailable = event => {
        if (event.data.size === 0 || session.discard) return
        session.plaintextBytes += event.data.size
        const maximumBytes = Math.min(
          capabilities.media!.maximumPlaintextBytes,
          VOICE_NOTE_MAX_PLAINTEXT_BYTES,
        )
        if (session.plaintextBytes > maximumBytes) {
          session.discard = true
          toast.error(t('chat.voice.tooLarge', { limit: formatBytes(maximumBytes) }))
          if (recorder.state !== 'inactive') recorder.stop()
          return
        }
        session.chunks.push(event.data)
      }
      recorder.onerror = () => {
        session.discard = true
        toast.error(t('chat.voice.failed'))
        if (recorder.state !== 'inactive') recorder.stop()
      }
      recorder.onstop = () => {
        const durationMs = Math.max(1, Date.now() - session.startedAt)
        releaseVoiceRecording(session)
        if (session.discard) {
          if (voiceMountedRef.current) setVoiceStopping(false)
          return
        }
        const recorderMimeType = recorder.mimeType || preferredMimeType ||
          session.chunks.find(chunk => chunk.type)?.type || 'audio/webm'
        const mimeType = canonicalVoiceNoteMimeType(recorderMimeType)
        const file = new File(session.chunks, voiceNoteFilename(mimeType), { type: mimeType })
        if (file.size === 0) {
          if (voiceMountedRef.current) {
            setVoiceStopping(false)
            toast.error(t('chat.voice.empty'))
          }
          return
        }
        void sendAttachmentFile(
          file,
          { durationMs },
          { conversation: session.conversation,
            disappearingTimerSeconds: session.disappearingTimerSeconds },
        ).finally(() => {
          if (voiceMountedRef.current) setVoiceStopping(false)
        })
      }
      recorder.start(1_000)
      setVoiceElapsedMs(0)
      setVoiceRecording(true)
      voiceTimerRef.current = window.setInterval(() => {
        const elapsed = Date.now() - session.startedAt
        setVoiceElapsedMs(Math.min(elapsed, VOICE_NOTE_MAX_DURATION_MS))
        if (elapsed >= VOICE_NOTE_MAX_DURATION_MS && recorder.state !== 'inactive') {
          toast.info(t('chat.voice.maximumReached'))
          stopVoiceRecording(false)
        }
      }, 250)
    } catch {
      stream?.getTracks().forEach(track => track.stop())
      if (voiceMountedRef.current) toast.error(t('chat.voice.permissionFailed'))
    } finally {
      voiceStartingRef.current = false
      if (voiceMountedRef.current) setVoiceStarting(false)
    }
  }

  async function updateDisappearingTimer(durationSeconds?: number) {
    if (!service || !selectedConversation || !canSetDisappearingTimer || timerSending) return
    setTimerSending(true)
    try {
      const summary = await service.sendDisappearingTimer(
        selectedConversation,
        durationSeconds,
      )
      if (summary.safetyNumberChanges.length > 0) {
        toast.warning(t('chat.safetyNumberChanged'))
      }
      setHistory(await service.history())
      toast.success(durationSeconds === undefined
        ? t('chat.disappearing.disabled')
        : t('chat.disappearing.enabled', {
            duration: disappearingPresetLabel(durationSeconds, t),
          }))
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setTimerSending(false)
    }
  }

  const startVisibleDisappearingMessage = useCallback((message: ChatHistoryEntry) => {
    const messageId = message.content.messageId
    if (
      !service
      || !pageVisible
      || message.direction !== 'incoming'
      || !messageId
      || message.content.expiresAfterSeconds === undefined
      || message.content.expiresAtMs !== undefined
      || expiryStartAttempted.current.has(messageId)
    ) return
    expiryStartAttempted.current.add(messageId)
    void service.startDisappearingExpiry(message.conversation, messageId)
      .catch(cause => console.warn('Encrypted disappearing expiry start could not be sent', cause))
      .then(() => service.history())
      .then(nextHistory => {
        setHistory(nextHistory)
        const durableStart = nextHistory.some(candidate =>
          candidate.content.messageId === messageId
          && candidate.content.expiresAtMs !== undefined)
        if (!durableStart) expiryStartAttempted.current.delete(messageId)
      })
      .catch(cause => {
        expiryStartAttempted.current.delete(messageId)
        console.warn('Disappearing expiry state could not be refreshed', cause)
      })
  }, [pageVisible, service])

  async function updateContact(action: 'accept' | 'reject' | 'block' | 'unblock') {
    if (!service || !selectedAddress || contactUpdating) return
    setContactUpdating(true)
    try {
      if (action === 'accept') await service.acceptContact(selectedAddress)
      if (action === 'reject') await service.rejectContact(selectedAddress)
      if (action === 'block') await service.blockContact(selectedAddress)
      if (action === 'unblock') await service.unblockContact(selectedAddress)
      const [nextHistory, nextContacts, nextProfiles] = await Promise.all([
        service.history(),
        service.contacts(),
        service.profiles(),
      ])
      setHistory(nextHistory)
      setContacts(nextContacts)
      setPeerProfiles(nextProfiles)
      if (action === 'reject') setSelectedConversation(null)
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setContactUpdating(false)
    }
  }

  async function saveProfile(
    displayName: string,
    avatar?: string,
    avatarContentType?: string,
  ) {
    if (!service) return
    const profile = await service.setProfile(displayName, avatar, avatarContentType)
    setLocalProfile(profile)
    toast.success(t('chat.profile.saved'))
  }

  async function createGroup(event: FormEvent) {
    event.preventDefault()
    if (!service || groupUpdating) return
    const parsed = parseAccountAddress(newGroupMember)
    const member = parsed ? withHomeServer(parsed, capabilities.serverName) : null
    if (!member?.server) {
      toast.error(t('chat.errors.invalidAddress'))
      return
    }
    setGroupUpdating(true)
    try {
      const group = await service.createGroup(member)
      setGroups(await service.groups())
      setGroupInvitations(await service.groupInvitations())
      setSelectedConversation({
        kind: 'group',
        groupId: group.request.genesis.conversationId,
      })
      setNewGroupMember('')
      setNewGroupOpen(false)
      toast.success('Encrypted group created')
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setGroupUpdating(false)
    }
  }

  async function respondGroupInvitation(
    invitation: PendingMlsInvitation,
    accept: boolean,
  ) {
    if (!service || groupUpdating) return
    setGroupUpdating(true)
    try {
      if (accept) await service.acceptGroupInvitation(invitation)
      else await service.rejectGroupInvitation(invitation)
      setGroups(await service.groups())
      setGroupInvitations(await service.groupInvitations())
      if (accept) {
        setSelectedConversation({ kind: 'group', groupId: invitation.conversationId })
      }
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setGroupUpdating(false)
    }
  }

  async function addMemberToSelectedGroup(event: FormEvent) {
    event.preventDefault()
    if (!service || !selectedGroup || groupUpdating) return
    const parsed = parseAccountAddress(groupMember)
    const member = parsed ? withHomeServer(parsed, capabilities.serverName) : null
    if (!member?.server) {
      toast.error(t('chat.errors.invalidAddress'))
      return
    }
    setGroupUpdating(true)
    try {
      await service.addGroupMember(selectedGroup.request.genesis.conversationId, member)
      setGroups(await service.groups())
      setGroupMember('')
      setAddGroupMemberOpen(false)
      toast.success('Member invited with MLS')
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setGroupUpdating(false)
    }
  }

  async function updateSelectedGroupMember(
    member: MlsConversationMember,
    action: 'administrator' | 'remove',
  ) {
    if (!service || !selectedGroup || !canManageSelectedGroup || groupUpdating) return
    setGroupUpdating(true)
    try {
      if (action === 'remove') {
        await service.removeGroupMember(
          selectedGroup.request.genesis.conversationId,
          member.address,
        )
        toast.success('Member removed with MLS')
      } else {
        await service.setGroupAdministrator(
          selectedGroup.request.genesis.conversationId,
          member.address,
          !member.isAdmin,
        )
        toast.success(member.isAdmin ? 'Administrator removed' : 'Administrator added')
      }
      setGroups(await service.groups())
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setGroupUpdating(false)
    }
  }

  async function updateSelectedGroupOwner(member: MlsConversationMember) {
    if (!service || !selectedGroup || !canManageSelectedGroupAuthorities || groupUpdating) return
    setGroupUpdating(true)
    try {
      const finalized = await service.setGroupOwner(
        selectedGroup.request.genesis.conversationId,
        member.address,
        !member.ownerId,
      )
      setGroups(await service.groups())
      setOwnerApprovalRequests(await service.pendingGroupOwnerApprovals())
      toast.success(finalized
        ? 'Owner role updated with MLS'
        : 'Encrypted approval requested from the other group owners')
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setGroupUpdating(false)
    }
  }

  async function respondOwnerApproval(approve: boolean) {
    if (!service || !selectedGroup || !selectedOwnerApproval || groupUpdating) return
    setGroupUpdating(true)
    try {
      if (approve) {
        await service.approveGroupOwnerGovernance(selectedGroup.request.genesis.conversationId)
      } else {
        await service.rejectGroupOwnerGovernance(selectedGroup.request.genesis.conversationId)
      }
      setOwnerApprovalRequests(await service.pendingGroupOwnerApprovals())
      setGroups(await service.groups())
      const action = selectedOwnerApproval.request.proposal.actionType === 7
        ? 'Group close'
        : selectedOwnerApproval.request.proposal.actionType === 9
          ? 'Group recovery'
          : selectedOwnerApproval.request.proposal.actionType === 5
            ? 'Sender policy change'
            : selectedOwnerApproval.request.proposal.actionType === 6
              ? 'Cryptographic policy change'
              : 'Owner change'
      toast.success(approve ? `${action} approved` : `${action} rejected on this device`)
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setGroupUpdating(false)
    }
  }

  async function updateSelectedGroupAuthorities(event: FormEvent) {
    event.preventDefault()
    if (!service || !selectedGroup || !canManageSelectedGroupAuthorities || groupUpdating) return
    const domains = groupAuthorityDomains
      .split(/[\s,]+/u)
      .map(domain => domain.trim())
      .filter(Boolean)
    setGroupUpdating(true)
    try {
      await service.setGroupAuthorities(
        selectedGroup.request.genesis.conversationId,
        domains,
      )
      setGroups(await service.groups())
      toast.success('MLS ordering authorities updated')
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setGroupUpdating(false)
    }
  }

  async function closeSelectedGroup() {
    if (!service || !selectedGroup || !canManageSelectedGroupAuthorities || groupUpdating) return
    const confirmed = window.confirm(
      'Close this MLS group? Closing is permanent for this incarnation and all current owners may need to approve.',
    )
    if (!confirmed) return
    setGroupUpdating(true)
    try {
      const finalized = await service.closeGroup(
        selectedGroup.request.genesis.conversationId,
      )
      setGroups(await service.groups())
      setOwnerApprovalRequests(await service.pendingGroupOwnerApprovals())
      toast.success(finalized
        ? 'MLS group closed'
        : 'Encrypted close approval requested from the other group owners')
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setGroupUpdating(false)
    }
  }

  async function updateSelectedGroupSenderPolicy(
    applicationSenders: 'members' | 'administrators',
  ) {
    if (!service || !selectedGroup || !canManageSelectedGroupAuthorities || groupUpdating) return
    setGroupUpdating(true)
    try {
      const finalized = await service.setGroupApplicationSenders(
        selectedGroup.request.genesis.conversationId,
        applicationSenders,
      )
      setGroups(await service.groups())
      setOwnerApprovalRequests(await service.pendingGroupOwnerApprovals())
      toast.success(finalized
        ? 'MLS sender policy updated'
        : 'Encrypted sender-policy approval requested from the other group owners')
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setGroupUpdating(false)
    }
  }

  async function tightenSelectedGroupPlaintext(event: FormEvent) {
    event.preventDefault()
    if (!service || !selectedGroup || !canManageSelectedGroupAuthorities || groupUpdating) return
    const maximumBytes = Number(groupMaximumPlaintext)
    setGroupUpdating(true)
    try {
      const finalized = await service.tightenGroupMaximumPlaintext(
        selectedGroup.request.genesis.conversationId,
        maximumBytes,
      )
      setGroups(await service.groups())
      setOwnerApprovalRequests(await service.pendingGroupOwnerApprovals())
      toast.success(finalized
        ? 'MLS cryptographic policy tightened'
        : 'Encrypted cryptographic-policy approval requested from the other group owners')
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setGroupUpdating(false)
    }
  }

  async function recoverSelectedGroup() {
    if (!service || !selectedGroup || !canManageSelectedGroupAuthorities || groupUpdating) return
    const confirmed = window.confirm(
      'Recover this MLS group into a fresh incarnation? Use this only when the current ordering quorum cannot make progress. The member and owner sets will be preserved, and all current owners may need to approve.',
    )
    if (!confirmed) return
    const domains = groupAuthorityDomains
      .split(/[\s,]+/u)
      .map(domain => domain.trim())
      .filter(Boolean)
    setGroupUpdating(true)
    try {
      const finalized = await service.recoverGroup(
        selectedGroup.request.genesis.conversationId,
        domains,
      )
      setGroups(await service.groups())
      setOwnerApprovalRequests(await service.pendingGroupOwnerApprovals())
      toast.success(finalized
        ? 'MLS group recovered into a fresh incarnation'
        : 'Encrypted recovery approval requested from the other group owners')
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setGroupUpdating(false)
    }
  }

  const showPeerList = !isMobile || !selectedConversation

  const resetThisBrowserChatDevice = () => {
    if (!auth.userId || deviceResetting) return
    setDeviceResetting(true)
    requestLocalChatDeviceReset(auth.userId)
    window.location.reload()
  }

  return (
    <div className="fixed inset-0 flex bg-background text-foreground">
      {showPeerList && (
        <aside className="flex w-full shrink-0 flex-col border-r bg-sidebar md:w-96">
          <header
            className="flex h-16 items-center gap-1 border-b px-2"
            data-testid="chat-sidebar-header"
          >
            <Button
              variant="ghost"
              size="icon"
              className="shrink-0"
              onClick={() => navigate('/drive')}
            >
              <ArrowLeft className="h-5 w-5" />
              <span className="sr-only">{t('chat.backToFiles')}</span>
            </Button>
            {selfAddress && (
              <ProfileEditor
                profile={localProfile}
                address={selfAddress}
                disabled={!service || loading}
                onSave={saveProfile}
              />
            )}
            <div className="min-w-0 flex-1">
              <h1
                className="truncate font-semibold"
                data-testid="chat-sidebar-title"
                title={t('chat.title')}
              >
                {t('chat.title')}
              </h1>
              <p
                className="truncate text-xs text-muted-foreground"
                data-testid="chat-device-status"
              >
                {t('chat.device', { device: service?.deviceId ?? '…' })}
              </p>
            </div>
            <Dialog open={devicesOpen} onOpenChange={setDevicesOpen}>
              <DialogTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="shrink-0"
                  disabled={!service}
                  aria-label={t('chat.devices.open')}
                  data-testid="chat-devices-button"
                >
                  <MonitorSmartphone className="h-5 w-5" />
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-lg">
                <DialogHeader>
                  <DialogTitle>{t('chat.devices.title')}</DialogTitle>
                  <DialogDescription>{t('chat.devices.description')}</DialogDescription>
                </DialogHeader>
                <label className="flex items-start gap-3 rounded-lg border p-3">
                  <input
                    type="checkbox"
                    className="mt-1 h-4 w-4 accent-primary"
                    checked={readReceiptsEnabled}
                    onChange={event => {
                      const enabled = event.target.checked
                      setReadReceiptsEnabled(enabled)
                      window.localStorage.setItem(
                        'kutup:chat:read-receipts',
                        enabled ? '1' : '0',
                      )
                    }}
                    data-testid="chat-read-receipts-toggle"
                  />
                  <span>
                    <span className="block text-sm font-medium">
                      {t('chat.receipts.setting')}
                    </span>
                    <span className="mt-1 block text-xs text-muted-foreground">
                      {t('chat.receipts.settingDescription')}
                    </span>
                  </span>
                </label>
                {devicesLoading ? (
                  <div className="flex items-center justify-center gap-2 py-10 text-sm text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    {t('chat.devices.loading')}
                  </div>
                ) : (
                  <div className="grid max-h-[55vh] gap-2 overflow-y-auto" data-testid="chat-devices-list">
                    {devices.map(device => {
                      const current = device.deviceId === service?.deviceId
                      const lastSeen = formatDeviceTime(device.lastSeenAt)
                      return (
                        <div
                          key={device.deviceId}
                          className="flex items-center gap-3 rounded-lg border p-3"
                          data-testid={`chat-device-${device.deviceId}`}
                        >
                          <MonitorSmartphone className="h-5 w-5 shrink-0 text-muted-foreground" />
                          <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="truncate text-sm font-medium">
                                {device.name || t('chat.device', { device: device.deviceId })}
                              </span>
                              {current && (
                                <span className="rounded-full bg-primary/10 px-2 py-0.5 text-[11px] font-medium text-primary">
                                  {t('chat.devices.current')}
                                </span>
                              )}
                            </div>
                            <p className="mt-1 text-xs text-muted-foreground">
                              {t('chat.devices.created', { time: formatDeviceTime(device.createdAt) })}
                              {' · '}
                              {lastSeen
                                ? t('chat.devices.lastSeen', { time: lastSeen })
                                : t('chat.devices.neverSeen')}
                            </p>
                          </div>
                          {!current && (
                            <Button
                              type="button"
                              size="sm"
                              variant="outline"
                              disabled={deviceRevoking !== null}
                              onClick={() => void revokeChatDevice(device)}
                              data-testid={`chat-device-revoke-${device.deviceId}`}
                            >
                              {deviceRevoking === device.deviceId
                                ? <Loader2 className="h-4 w-4 animate-spin" />
                                : t('chat.devices.revoke')}
                            </Button>
                          )}
                        </div>
                      )
                    })}
                  </div>
                )}
                <div className="grid gap-2 border-t pt-4" data-testid="chat-history-backup-status">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <h3 className="text-sm font-medium">{t('chat.backup.title')}</h3>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {t('chat.backup.recovery')}
                      </p>
                    </div>
                    <span className={cn(
                      'rounded-full px-2.5 py-1 text-xs font-medium',
                      backupStatus?.state === 'needsAttention'
                        ? 'bg-destructive/10 text-destructive'
                        : backupStatus?.state === 'offline'
                          ? 'bg-muted text-muted-foreground'
                          : 'bg-primary/10 text-primary',
                    )} data-testid="chat-backup-state"
                    data-current-cursor={backupStatus?.currentCursor ?? 0}>
                      {backupStatusLabel(backupStatus, t)}
                    </span>
                  </div>
                  <p className="text-xs text-muted-foreground" data-testid="chat-backup-latest-protected">
                    {t('chat.backup.latestProtected', {
                      time: backupStatus?.latestProtectedAt
                        ? new Date(backupStatus.latestProtectedAt).toLocaleString()
                        : t('chat.backup.waiting'),
                    })}
                  </p>
                  {(backupStatus?.pendingEvents ?? 0) > 0 && (
                    <p className="text-xs text-warning">
                      {t('chat.backup.pending', {
                        count: backupStatus!.pendingEvents,
                        bytes: formatBytes(backupStatus!.pendingBytes),
                      })}
                    </p>
                  )}
                  {backupStatus?.state === 'needsAttention' && (
                    <div className="rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-xs">
                      {t(backupStatus.storageFull ? 'chat.backup.full' : 'chat.backup.attention')}
                    </div>
                  )}
                </div>
              </DialogContent>
            </Dialog>
            {capabilities.media && (
              <Dialog open={mediaStorageOpen} onOpenChange={setMediaStorageOpen}>
                <DialogTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="shrink-0"
                    disabled={!service}
                    aria-label={t('chat.backup.storageAria')}
                    data-testid="chat-storage-button"
                  >
                    <HardDrive className="h-5 w-5" />
                  </Button>
                </DialogTrigger>
                <DialogContent className="max-w-lg">
                  <DialogHeader>
                    <DialogTitle>{t('chat.backup.storageTitle')}</DialogTitle>
                    <DialogDescription>
                      {capabilities.backup?.deliveryMediaRetentionDays === 0
                        ? t('chat.backup.storageDescriptionUnlimited')
                        : t('chat.backup.storageDescription', {
                            days: capabilities.backup?.deliveryMediaRetentionDays ?? 45,
                          })}
                    </DialogDescription>
                  </DialogHeader>
                  {mediaStorageLoading || !mediaStorage ? (
                    <div className="flex items-center justify-center gap-2 py-10 text-sm text-muted-foreground">
                      <Loader2 className="h-4 w-4 animate-spin" /> {t('chat.backup.loading')}
                    </div>
                  ) : (
                    <div className="grid gap-4" data-testid="chat-storage-summary">
                      <div className="rounded-lg border p-4">
                        <div className="flex justify-between text-sm font-medium">
                          <span>{t('chat.backup.used', { bytes: formatBytes(backupStatus?.storage.usedBytes ?? mediaStorage.totalUsedBytes) })}</span>
                          <span>{formatBytes(backupStatus?.storage.quotaBytes ?? mediaStorage.totalQuotaBytes)}</span>
                        </div>
                        <div className="mt-3 h-2 overflow-hidden rounded-full bg-muted">
                          <div
                            className="h-full bg-primary"
                            style={{ width: `${Math.min(100, (backupStatus?.storage.quotaBytes ?? mediaStorage.totalQuotaBytes) > 0
                              ? (backupStatus?.storage.usedBytes ?? mediaStorage.totalUsedBytes) * 100 /
                                (backupStatus?.storage.quotaBytes ?? mediaStorage.totalQuotaBytes)
                              : 0)}%` }}
                          />
                        </div>
                        <div className="mt-3 grid grid-cols-2 gap-3 text-sm">
                          <div className="rounded bg-muted/50 p-2">
                            <span className="block text-xs text-muted-foreground">{t('chat.backup.messageHistory')}</span>
                            {formatBytes(backupStatus?.storage.messageBytes ?? 0)}
                          </div>
                          <div className="rounded bg-muted/50 p-2">
                            <span className="block text-xs text-muted-foreground">{t('chat.backup.deliveryMedia')}</span>
                            {formatBytes(backupStatus?.storage.deliveryMediaBytes ?? mediaStorage.chatMediaBytes)}
                          </div>
                          <div className="rounded bg-muted/50 p-2">
                            <span className="block text-xs text-muted-foreground">{t('chat.backup.historyMedia')}</span>
                            {formatBytes(backupStatus?.storage.historyMediaBytes ?? 0)}
                          </div>
                        </div>
                      </div>
                      <div className="grid max-h-72 gap-2 overflow-y-auto">
                        {mediaStorage.byConversation.map(item => {
                          const profile = profilesByPeer.get(item.conversationReference)
                          const group = groups.find(candidate =>
                            candidate.request.genesis.conversationId === item.conversationReference)
                          const label = item.conversationReference === selfAddress
                            ? t('chat.noteToSelf')
                            : profile?.displayName
                              ?? (group ? `Group ${item.conversationReference.slice(0, 8)}`
                                : item.conversationReference)
                          return (
                            <div
                              key={item.conversationReference}
                              className="flex items-center justify-between gap-3 rounded-lg border px-3 py-2 text-sm"
                            >
                              <span className="min-w-0 truncate">{label}</span>
                              <span className="ml-auto shrink-0 text-muted-foreground">{formatBytes(item.bytes)}</span>
                              <Button
                                type="button"
                                size="sm"
                                variant="outline"
                                disabled={mediaStorageClearing !== null}
                                onClick={() => {
                                  if (!service || !window.confirm(
                                    `Clear stored Chat media for ${label}? Messages remain, but downloaded files may become unavailable.`,
                                  )) return
                                  setMediaStorageClearing(item.conversationReference)
                                  void service.clearChatMediaConversation(item.conversationReference)
                                    .then(setMediaStorage)
                                    .catch(cause => toast.error(errorMessage(cause, t)))
                                    .finally(() => setMediaStorageClearing(null))
                                }}
                                aria-label={`Clear stored Chat media for ${label}`}
                              >
                                {mediaStorageClearing === item.conversationReference
                                  ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                  : 'Clear'}
                              </Button>
                            </div>
                          )
                        })}
                        {mediaStorage.byConversation.length === 0 && (
                          <p className="py-5 text-center text-sm text-muted-foreground">
                            No categorized Chat attachments yet.
                          </p>
                        )}
                      </div>
                    </div>
                  )}
                </DialogContent>
              </Dialog>
            )}
            {selfAccount?.server && selfAddress && (
              <Dialog>
                <DialogTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="shrink-0"
                    aria-label={t('chat.contact.open')}
                  >
                    <QrCode className="h-5 w-5" />
                  </Button>
                </DialogTrigger>
                <DialogContent className="max-w-sm">
                  <DialogHeader>
                    <DialogTitle>{t('chat.contact.title')}</DialogTitle>
                    <DialogDescription>{t('chat.contact.description')}</DialogDescription>
                  </DialogHeader>
                  <div className="flex flex-col items-center gap-4 py-2">
                    <div className="rounded-xl bg-white p-4">
                      <QRCodeSVG value={contactUri(selfAccount)} size={200} />
                    </div>
                    <code className="max-w-full break-all rounded bg-muted px-3 py-2 text-sm">
                      {selfAddress}
                    </code>
                    <Button
                      className="w-full"
                      onClick={() =>
                        void copyText(selfAddress).then(() => toast.success(t('chat.contact.copied')))
                      }
                    >
                      <Copy className="mr-2 h-4 w-4" />
                      {t('chat.contact.copy')}
                    </Button>
                  </div>
                </DialogContent>
              </Dialog>
            )}
            {capabilities.mlsGroups && (
              <Dialog open={newGroupOpen} onOpenChange={setNewGroupOpen}>
                <DialogTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="shrink-0"
                    disabled={!service}
                    aria-label="Create encrypted group"
                    data-testid="chat-create-group"
                  >
                    <Plus className="h-5 w-5" />
                  </Button>
                </DialogTrigger>
                <DialogContent className="max-w-md">
                  <form className="grid gap-4" onSubmit={createGroup}>
                    <DialogHeader>
                      <DialogTitle>Create encrypted group</DialogTitle>
                      <DialogDescription>
                        The first member is invited with an authenticated MLS Welcome. More members can be added later.
                      </DialogDescription>
                    </DialogHeader>
                    <Input
                      value={newGroupMember}
                      onChange={event => setNewGroupMember(event.target.value)}
                      placeholder="member@example.com"
                      aria-label="Initial group member"
                      data-testid="chat-group-initial-member"
                      autoCapitalize="none"
                      autoCorrect="off"
                    />
                    <DialogFooter>
                      <Button
                        type="submit"
                        disabled={!parseAccountAddress(newGroupMember) || groupUpdating}
                        data-testid="chat-group-create-submit"
                      >
                        {groupUpdating && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                        Create group
                      </Button>
                    </DialogFooter>
                  </form>
                </DialogContent>
              </Dialog>
            )}
          </header>

          <form className="flex gap-2 border-b p-3" onSubmit={startConversation}>
            <Dialog open={searchOpen} onOpenChange={setSearchOpen}>
              <DialogTrigger asChild>
                <Button
                  type="button"
                  variant="outline"
                  size="icon"
                  className="shrink-0"
                  disabled={loading}
                  aria-label={t('chat.search.open')}
                  data-testid="chat-search-open"
                >
                  <Search className="h-4 w-4" />
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-xl">
                <DialogHeader>
                  <DialogTitle>{t('chat.search.title')}</DialogTitle>
                  <DialogDescription>{t('chat.search.description')}</DialogDescription>
                </DialogHeader>
                <div className="relative">
                  <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    value={searchQuery}
                    onChange={event => setSearchQuery(event.target.value)}
                    placeholder={t('chat.search.placeholder')}
                    className="pl-9"
                    autoFocus
                    data-testid="chat-search-input"
                  />
                </div>
                <p className="text-xs text-muted-foreground">{t('chat.search.private')}</p>
                <div
                  className="grid max-h-[55vh] gap-1 overflow-y-auto"
                  data-testid="chat-search-results"
                >
                  {!searchQuery.trim() && (
                    <p className="py-10 text-center text-sm text-muted-foreground">
                      {t('chat.search.prompt')}
                    </p>
                  )}
                  {searchQuery.trim() && searchResults.length === 0 && (
                    <p className="py-10 text-center text-sm text-muted-foreground">
                      {t('chat.search.empty')}
                    </p>
                  )}
                  {searchResults.map(result => {
                    const address = directAddress(result.message.conversation)
                    const label = address === selfAddress
                      ? t('chat.noteToSelf')
                      : address
                        ? profilesByPeer.get(address)?.displayName || address
                        : `Group ${result.message.conversation.kind === 'group'
                          ? result.message.conversation.groupId.slice(0, 8)
                          : ''}`
                    return (
                      <button
                        key={`${result.message.direction}:${result.message.id}`}
                        type="button"
                        className="rounded-lg px-3 py-3 text-left transition-colors hover:bg-accent focus-visible:bg-accent"
                        onClick={() => openSearchResult(result.message)}
                        data-testid="chat-search-result"
                      >
                        <span className="flex items-center justify-between gap-3">
                          <span className="truncate text-xs font-medium text-muted-foreground">
                            {label}
                          </span>
                          <span className="shrink-0 text-[11px] text-muted-foreground">
                            {formatTime(result.message.content.sentAt)}
                          </span>
                        </span>
                        <span className="mt-1 block line-clamp-2 text-sm">{result.preview}</span>
                      </button>
                    )
                  })}
                </div>
              </DialogContent>
            </Dialog>
            <Input
              value={newPeer}
              onChange={(event) => setNewPeer(event.target.value)}
              placeholder={t('chat.username')}
              aria-label={t('chat.startAria')}
              autoCapitalize="none"
              autoCorrect="off"
            />
            <Button type="submit" size="icon" disabled={!parseAccountAddress(newPeer)}>
              <Plus className="h-4 w-4" />
              <span className="sr-only">{t('chat.start')}</span>
            </Button>
          </form>

          {requests.length > 0 && (
            <div className="border-b p-2">
              <div className="flex items-center gap-2 px-3 py-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                <MessageSquareWarning className="h-4 w-4" />
                {t('chat.requests.title', { count: requests.length })}
              </div>
              {requests.map(({ contact, conversation, message }) => {
                const profile = profilesByPeer.get(contact.peer)
                return (
                <button
                  key={contact.peer}
                  type="button"
                  onClick={() => setSelectedConversation(conversation)}
                  className={cn(
                    'flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left transition-colors',
                    selectedAddress === contact.peer ? 'bg-warning-faint' : 'hover:bg-accent',
                  )}
                >
                  <ProfileAvatar
                    profile={profile}
                    address={contact.peer}
                    className="h-10 w-10 bg-warning-faint text-warning"
                  />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium">
                      {profile?.displayName || contact.peer}
                    </span>
                    {profile?.displayName && (
                      <span className="block truncate text-[11px] text-muted-foreground">
                        {contact.peer}
                      </span>
                    )}
                    <span className="block truncate text-xs text-muted-foreground">
                      {message
                        ? replyPreview(
                            message,
                            t('chat.newerClient'),
                            message.content.messageId
                              ? mutationsByMessageId.get(message.content.messageId)
                              : undefined,
                            t('chat.mutations.deleted'),
                          )
                        : t('chat.newerClient')}
                    </span>
                  </span>
                </button>
                )
              })}
            </div>
          )}

          {groupInvitations.length > 0 && (
            <div className="border-b p-2" data-testid="chat-group-invitations">
              <div className="flex items-center gap-2 px-3 py-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                <MessageSquareWarning className="h-4 w-4" />
                Encrypted group invitations ({groupInvitations.length})
              </div>
              {groupInvitations.map(invitation => (
                <div
                  key={`${invitation.conversationId}:${invitation.incarnation}`}
                  className="grid gap-2 rounded-lg px-3 py-3"
                >
                  <code className="truncate text-xs">
                    Group {invitation.conversationId.slice(0, 8)}
                  </code>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      disabled={groupUpdating}
                      onClick={() => void respondGroupInvitation(invitation, true)}
                      data-testid="chat-group-accept"
                    >
                      Accept
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={groupUpdating}
                      onClick={() => void respondGroupInvitation(invitation, false)}
                    >
                      Reject
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {(groups.length > 0 || restoredHistoryGroups.length > 0) && (
            <div className="border-b p-2" data-testid="chat-groups">
              <div className="px-3 py-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                MLS groups
              </div>
              {groups.filter(group =>
                group.status === 'active' || group.status === 'closed').map(group => {
                const groupId = group.request.genesis.conversationId
                const conversation: ConversationId = { kind: 'group', groupId }
                const latest = visibleHistory.filter(message =>
                  conversationKey(message.conversation) === conversationKey(conversation)).at(-1)
                return (
                  <button
                    key={groupId}
                    type="button"
                    onClick={() => setSelectedConversation(conversation)}
                    className={cn(
                      'flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left transition-colors',
                      selectedKey === conversationKey(conversation)
                        ? 'bg-primary/10'
                        : 'hover:bg-accent',
                    )}
                    data-testid={`chat-group-${groupId}`}
                  >
                    <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-primary/15 text-primary">
                      <MessageCircle className="h-5 w-5" />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium">
                        Group {groupId.slice(0, 8)}{group.status === 'closed' ? ' · Closed' : ''}
                      </span>
                      <span className="block truncate text-xs text-muted-foreground">
                        {latest
                          ? replyPreview(
                              latest,
                              t('chat.newerClient'),
                              latest.content.messageId
                                ? mutationsByMessageId.get(latest.content.messageId)
                                : undefined,
                              t('chat.mutations.deleted'),
                            )
                          : `${group.currentRoster.length} members · epoch ${group.lastFinalizedEpoch}`}
                      </span>
                    </span>
                  </button>
                )
              })}
              {restoredHistoryGroups.map(({ groupId, message }) => {
                const conversation: ConversationId = { kind: 'group', groupId }
                return (
                  <button
                    key={`restored:${groupId}`}
                    type="button"
                    onClick={() => setSelectedConversation(conversation)}
                    className={cn(
                      'flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left transition-colors',
                      selectedKey === conversationKey(conversation)
                        ? 'bg-primary/10'
                        : 'hover:bg-accent',
                    )}
                    data-testid={`chat-group-${groupId}`}
                  >
                    <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-primary/15 text-primary">
                      <MessageCircle className="h-5 w-5" />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium">
                        Group {groupId.slice(0, 8)} · Protected history
                      </span>
                      <span className="block truncate text-xs text-muted-foreground">
                        {replyPreview(
                          message,
                          t('chat.newerClient'),
                          message.content.messageId
                            ? mutationsByMessageId.get(message.content.messageId)
                            : undefined,
                          t('chat.mutations.deleted'),
                        )}
                      </span>
                    </span>
                  </button>
                )
              })}
            </div>
          )}

          {selfAccount && (
            <div className="border-b p-2">
              <button
                type="button"
                onClick={() => setSelectedConversation(directConversation(selfAccount))}
                className={cn(
                  'flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left transition-colors',
                  noteSelected ? 'bg-primary/10' : 'hover:bg-accent',
                )}
              >
                <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-primary/15 text-primary">
                  <Bookmark className="h-5 w-5" />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-medium">
                    {t('chat.noteToSelf')}
                  </span>
                  <span className="block truncate text-xs text-muted-foreground">
                    {t('chat.noteToSelfDescription')}
                  </span>
                </span>
              </button>
            </div>
          )}

          <div className="flex-1 overflow-y-auto p-2">
            {loading && (
              <div className="flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" /> {t('chat.preparing')}
              </div>
            )}
            {!loading && peers.length === 0 && (
              <div className="px-6 py-12 text-center text-sm text-muted-foreground">
                <MessageCircle className="mx-auto mb-3 h-9 w-9 opacity-50" />
                {t('chat.empty')}
              </div>
            )}
            {peers.map(({ conversation, message }) => {
              const key = conversationKey(conversation)
              const label = directAddress(conversation) ??
                (conversation.kind === 'group' ? conversation.groupId : '')
              const profile = profilesByPeer.get(label)
              return (
              <button
                key={key}
                type="button"
                onClick={() => setSelectedConversation(conversation)}
                className={cn(
                  'flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left transition-colors',
                  selectedKey === key ? 'bg-primary/10' : 'hover:bg-accent',
                )}
              >
                <ProfileAvatar
                  profile={profile}
                  address={label}
                  className="h-10 w-10 bg-primary/15 text-primary"
                />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-medium">
                    {profile?.displayName || label}
                  </span>
                  {profile?.displayName && (
                    <span className="block truncate text-[11px] text-muted-foreground">
                      {label}
                    </span>
                  )}
                  <span className="block truncate text-xs text-muted-foreground">
                    {replyPreview(
                      message,
                      t('chat.newerClient'),
                      message.content.messageId
                        ? mutationsByMessageId.get(message.content.messageId)
                        : undefined,
                      t('chat.mutations.deleted'),
                    )}
                  </span>
                </span>
                <span className="text-[11px] text-muted-foreground">
                  {formatTime(message.content.sentAt)}
                </span>
              </button>
              )
            })}
          </div>
        </aside>
      )}

      {(!isMobile || selectedConversation) && (
        <main className="flex min-w-0 flex-1 flex-col">
          <header className="flex h-16 shrink-0 items-center gap-3 border-b bg-card px-4">
            {isMobile && (
              <Button variant="ghost" size="icon" onClick={() => setSelectedConversation(null)}>
                <ArrowLeft className="h-5 w-5" />
              </Button>
            )}
            {noteSelected ? (
              <span className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/15 text-primary">
                <Bookmark className="h-4 w-4" />
              </span>
            ) : (
              <ProfileAvatar
                profile={selectedProfile}
                address={selectedLabel}
                className="h-9 w-9 bg-primary/15 text-primary"
              />
            )}
            <div className="min-w-0 flex-1">
              <h2 className="truncate font-semibold">{selectedTitle}</h2>
              {!noteSelected && selectedProfile?.displayName && (
                <p className="truncate text-xs text-muted-foreground">{selectedLabel}</p>
              )}
            </div>
            {selectedAddress && !noteSelected && selectedSafety && service && (
              <SafetyVerificationDialog
                peer={selectedAddress}
                safety={selectedSafety}
                onVerify={async scannedPayload => {
                  const verified = await service.verifySafetyNumber(selectedAddress, scannedPayload)
                  setSelectedSafety(verified)
                  return verified
                }}
              />
            )}
            {selectedAddress && !noteSelected && !selectedSafety && (
              <Shield
                className="h-4 w-4 shrink-0 text-muted-foreground"
                aria-label="Encrypted identity has not been pinned yet"
              />
            )}
            {(noteSelected || selectedGroup || selectedRestoredHistoryGroup) && (
              <ShieldCheck
                className="h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400"
                aria-label="End-to-end encrypted"
              />
            )}
            {selectedConversation && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    type="button"
                    variant={selectedTimerSeconds === undefined ? 'ghost' : 'secondary'}
                    size="icon"
                    disabled={!service || !canSetDisappearingTimer || timerSending}
                    aria-label={t('chat.disappearing.setting')}
                    title={selectedTimerSeconds === undefined
                      ? t('chat.disappearing.off')
                      : t('chat.disappearing.active', {
                          duration: disappearingPresetLabel(selectedTimerSeconds, t),
                        })}
                    data-testid="chat-disappearing-timer"
                  >
                    {timerSending
                      ? <Loader2 className="h-4 w-4 animate-spin" />
                      : <Timer className="h-4 w-4" />}
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" data-testid="chat-disappearing-menu">
                  {DISAPPEARING_PRESETS.map(option => (
                    <DropdownMenuItem
                      key={option.key}
                      onSelect={() => void updateDisappearingTimer(option.durationSeconds)}
                      data-testid={`chat-disappearing-${option.key}`}
                    >
                      <span className="flex-1">
                        {t(`chat.disappearing.presets.${option.key}`)}
                      </span>
                      {selectedTimerSeconds === option.durationSeconds && (
                        <Check className="ml-3 h-4 w-4" />
                      )}
                    </DropdownMenuItem>
                  ))}
                </DropdownMenuContent>
              </DropdownMenu>
            )}
            {selectedGroup && (
              <Dialog open={groupMembersOpen} onOpenChange={setGroupMembersOpen}>
                <DialogTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    disabled={!service || groupUpdating}
                    aria-label="Group members"
                    data-testid="chat-group-members"
                  >
                    <Users className="h-4 w-4" />
                  </Button>
                </DialogTrigger>
                <DialogContent className="max-h-[90vh] max-w-3xl overflow-y-auto">
                  <DialogHeader>
                    <DialogTitle>MLS group members</DialogTitle>
                    <DialogDescription>
                      Administrator roles are encrypted into the MLS control state. Owners cannot be changed by a routine administrator action.
                    </DialogDescription>
                  </DialogHeader>
                  {selectedOwnerApproval && (
                    <div
                      className="rounded-lg border border-primary/40 bg-primary/5 p-3"
                      data-testid="chat-group-owner-approval"
                    >
                      <p className="text-sm font-medium">
                        {selectedOwnerApproval.request.proposal.actionType === 7
                          ? 'Approve closing this MLS group?'
                          : selectedOwnerApproval.request.proposal.actionType === 9
                            ? 'Approve MLS group recovery?'
                            : selectedOwnerApproval.request.proposal.actionType === 5
                              ? 'Approve who may send messages?'
                              : selectedOwnerApproval.request.proposal.actionType === 6
                                ? 'Approve stricter MLS message limits?'
                                : 'Approve MLS owner change?'}
                      </p>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {selectedOwnerApproval.request.proposal.actionType === 7
                          ? `${canonicalAccountAddress(selectedOwnerApproval.requester)} proposes permanently closing this group incarnation. Approval signs the exact unchanged-roster MLS transition.`
                          : selectedOwnerApproval.request.proposal.actionType === 9
                            ? `${canonicalAccountAddress(selectedOwnerApproval.requester)} proposes replacing the unavailable MLS incarnation while preserving the exact member and owner sets. Approval signs the complete new genesis and delivery commitments.`
                            : selectedOwnerApproval.request.proposal.actionType === 5
                              ? `${canonicalAccountAddress(selectedOwnerApproval.requester)} proposes allowing ${
                                selectedOwnerApproval.request.nextAuthorizationPolicy?.applicationSenders === 2
                                  ? 'only administrators'
                                  : 'all members'
                              } to send user-visible messages. Approval signs this exact encrypted policy transition.`
                              : selectedOwnerApproval.request.proposal.actionType === 6
                                ? `${canonicalAccountAddress(selectedOwnerApproval.requester)} proposes limiting canonical application plaintext to ${selectedOwnerApproval.request.nextCryptographicPolicy?.maximumApplicationPlaintextBytes ?? 0} bytes. Approval signs this exact encrypted policy transition.`
                                : `${canonicalAccountAddress(selectedOwnerApproval.requester)} proposes making ${selectedOwnerApproval.request.nextRoster
                                  .filter(member => Boolean(member.ownerId))
                                  .map(member => canonicalAccountAddress(member.address))
                                  .join(', ')} the group owners. Approval signs this exact encrypted transition.`}
                      </p>
                      <div className="mt-3 flex justify-end gap-2">
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          disabled={groupUpdating}
                          onClick={() => void respondOwnerApproval(false)}
                          data-testid="chat-group-owner-reject"
                        >
                          Reject
                        </Button>
                        <Button
                          type="button"
                          size="sm"
                          disabled={groupUpdating}
                          onClick={() => void respondOwnerApproval(true)}
                          data-testid="chat-group-owner-approve"
                        >
                          Approve
                        </Button>
                      </div>
                    </div>
                  )}
                  <div className="grid gap-2">
                    {selectedGroup.currentRoster.map(member => {
                      const address = canonicalAccountAddress(member.address)
                      const isSelf = address === selfAddress
                      const invitationFeedback = selectedGroupInvitationFeedback.find(feedback =>
                        canonicalAccountAddress(feedback.member) === address)
                      const canDemote = member.isAdmin
                        && !member.ownerId
                        && selectedGroupAdministratorCount > 1
                      return (
                        <div
                          key={address}
                          className="flex items-center gap-3 rounded-lg border p-3"
                          data-testid={`chat-group-member-${address}`}
                        >
                          <span className="min-w-0 flex-1">
                            <span className="block truncate text-sm font-medium">{address}</span>
                            <span className="mt-1 flex gap-2 text-xs text-muted-foreground">
                              {member.ownerId && (
                                <span data-testid={`chat-group-member-owner-${address}`}>Owner</span>
                              )}
                              {member.isAdmin && <span>Administrator</span>}
                              {isSelf && <span>You</span>}
                            </span>
                            {invitationFeedback?.decision === 'accepted' && (
                              <span
                                className="mt-1 block text-xs text-emerald-600 dark:text-emerald-400"
                                data-testid={`chat-group-invitation-feedback-${address}`}
                              >
                                Accepted the encrypted invitation
                              </span>
                            )}
                            {invitationFeedback && invitationFeedback.decision !== 'accepted' && (
                              <span
                                className="mt-1 block text-xs text-warning"
                                data-testid={`chat-group-invitation-feedback-${address}`}
                              >
                                {invitationFeedback.decision === 'rejected'
                                  ? 'Rejected the invitation'
                                  : 'Invitation expired'} · remove this member with MLS
                              </span>
                            )}
                          </span>
                          {canManageSelectedGroup && !isSelf && (
                            <>
                              {canManageSelectedGroupAuthorities && (
                                <Button
                                  type="button"
                                  size="sm"
                                  variant="outline"
                                  disabled={groupUpdating}
                                  onClick={() => void updateSelectedGroupOwner(member)}
                                  aria-label={`${member.ownerId ? 'Remove owner from' : 'Make owner'} ${address}`}
                                  data-testid={`chat-group-owner-${address}`}
                                >
                                  <ShieldCheck className="mr-2 h-4 w-4" />
                                  {member.ownerId ? 'Unown' : 'Owner'}
                                </Button>
                              )}
                              <Button
                                type="button"
                                size="sm"
                                variant="outline"
                                disabled={groupUpdating || (member.isAdmin && !canDemote)}
                                onClick={() => void updateSelectedGroupMember(member, 'administrator')}
                                aria-label={`${member.isAdmin ? 'Remove administrator from' : 'Make administrator'} ${address}`}
                              >
                                <Shield className="mr-2 h-4 w-4" />
                                {member.isAdmin ? 'Demote' : 'Promote'}
                              </Button>
                              <Button
                                type="button"
                                size="icon"
                                variant="ghost"
                                disabled={groupUpdating || Boolean(member.ownerId)}
                                onClick={() => void updateSelectedGroupMember(member, 'remove')}
                                aria-label={`Remove ${address} from group`}
                              >
                                <UserMinus className="h-4 w-4" />
                              </Button>
                            </>
                          )}
                        </div>
                      )
                    })}
                  </div>
                  <MlsGroupSecurityDetails
                    group={selectedGroup}
                    authorityPolicies={groupAuthorityPolicies}
                    loading={groupAuthorityPoliciesLoading}
                  />
                  {canManageSelectedGroupAuthorities && (
                    <form
                      className="flex gap-2 rounded-lg border p-3"
                      onSubmit={updateSelectedGroupAuthorities}
                    >
                      <Input
                        value={groupAuthorityDomains}
                        onChange={event => setGroupAuthorityDomains(event.target.value)}
                        placeholder="one.example, two.example"
                        aria-label="MLS ordering authority domains"
                        data-testid="chat-group-authority-domains"
                        autoCapitalize="none"
                        autoCorrect="off"
                      />
                      <Button
                        type="submit"
                        size="sm"
                        disabled={groupUpdating || groupAuthorityDomains.trim().length === 0}
                        data-testid="chat-group-save-authorities"
                      >
                        {groupUpdating && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                        Update
                      </Button>
                    </form>
                  )}
                  <div className="rounded-lg border p-3" data-testid="chat-group-policies">
                    <p className="text-sm font-medium">Private group policy</p>
                    <p className="mt-1 text-xs text-muted-foreground">
                      Sender policy sequence {selectedGroup.currentAuthorizationPolicy.sequence} ·
                      cryptographic policy sequence {selectedGroup.currentCryptographicPolicy.sequence}
                    </p>
                    <div className="mt-3 flex flex-wrap items-center gap-2">
                      <span className="text-xs text-muted-foreground">User-visible messages:</span>
                      <Button
                        type="button"
                        size="sm"
                        variant={selectedGroup.currentAuthorizationPolicy.applicationSenders === 1
                          ? 'default'
                          : 'outline'}
                        disabled={
                          groupUpdating
                          || !canManageSelectedGroupAuthorities
                          || selectedGroup.currentAuthorizationPolicy.applicationSenders === 1
                        }
                        onClick={() => void updateSelectedGroupSenderPolicy('members')}
                        data-testid="chat-group-senders-members"
                      >
                        All members
                      </Button>
                      <Button
                        type="button"
                        size="sm"
                        variant={selectedGroup.currentAuthorizationPolicy.applicationSenders === 2
                          ? 'default'
                          : 'outline'}
                        disabled={
                          groupUpdating
                          || !canManageSelectedGroupAuthorities
                          || selectedGroup.currentAuthorizationPolicy.applicationSenders === 2
                        }
                        onClick={() => void updateSelectedGroupSenderPolicy('administrators')}
                        data-testid="chat-group-senders-administrators"
                      >
                        Administrators only
                      </Button>
                    </div>
                    <form
                      className="mt-3 flex items-center gap-2"
                      onSubmit={tightenSelectedGroupPlaintext}
                    >
                      <Input
                        type="number"
                        min={1024}
                        max={selectedGroup.currentCryptographicPolicy.maximumApplicationPlaintextBytes - 1}
                        value={groupMaximumPlaintext}
                        onChange={event => setGroupMaximumPlaintext(event.target.value)}
                        aria-label="Maximum MLS application plaintext bytes"
                        data-testid="chat-group-maximum-plaintext"
                        disabled={!canManageSelectedGroupAuthorities || groupUpdating}
                      />
                      <Button
                        type="submit"
                        size="sm"
                        disabled={
                          !canManageSelectedGroupAuthorities
                          || groupUpdating
                          || !Number.isSafeInteger(Number(groupMaximumPlaintext))
                          || Number(groupMaximumPlaintext) < 1024
                          || Number(groupMaximumPlaintext)
                            >= selectedGroup.currentCryptographicPolicy.maximumApplicationPlaintextBytes
                        }
                        data-testid="chat-group-tighten-plaintext"
                      >
                        Tighten
                      </Button>
                    </form>
                    <p className="mt-2 text-xs text-muted-foreground">
                      Suite 0x0003, anonymous delivery, 1024-byte padding, and two retained past
                      epochs are mandatory in V1. The user-message plaintext maximum can only
                      decrease; typed governance controls retain the fixed V1 control limit.
                    </p>
                  </div>
                  {selectedGroupClosed ? (
                    <div
                      className="rounded-lg border border-destructive/40 bg-destructive-faint p-3 text-sm"
                      data-testid="chat-group-closed"
                    >
                      This MLS group incarnation is closed. Its authenticated history remains available, but no new messages or control changes are allowed.
                    </div>
                  ) : canManageSelectedGroupAuthorities ? (
                    <div className="flex flex-wrap justify-end gap-2 border-t pt-4">
                      <Button
                        type="button"
                        variant="outline"
                        disabled={groupUpdating || groupAuthorityDomains.trim().length === 0}
                        onClick={() => void recoverSelectedGroup()}
                        data-testid="chat-group-recover"
                      >
                        <RefreshCw className="mr-2 h-4 w-4" />
                        Recover quorum
                      </Button>
                      <Button
                        type="button"
                        variant="destructive"
                        disabled={groupUpdating}
                        onClick={() => void closeSelectedGroup()}
                        data-testid="chat-group-close"
                      >
                        <Trash2 className="mr-2 h-4 w-4" />
                        Close group
                      </Button>
                    </div>
                  ) : null}
                </DialogContent>
              </Dialog>
            )}
            {selectedGroup && canManageSelectedGroup && !selectedGroupClosed && (
              <Dialog open={addGroupMemberOpen} onOpenChange={setAddGroupMemberOpen}>
                <DialogTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    disabled={!service || groupUpdating}
                    aria-label="Add group member"
                    data-testid="chat-group-add-member"
                  >
                    <Plus className="h-4 w-4" />
                  </Button>
                </DialogTrigger>
                <DialogContent className="max-w-md">
                  <form className="grid gap-4" onSubmit={addMemberToSelectedGroup}>
                    <DialogHeader>
                      <DialogTitle>Add MLS group member</DialogTitle>
                      <DialogDescription>
                        A fresh KeyPackage is bound to the account-signed manifest before the membership commit is ordered.
                      </DialogDescription>
                    </DialogHeader>
                    <Input
                      value={groupMember}
                      onChange={event => setGroupMember(event.target.value)}
                      placeholder="member@example.com"
                      aria-label="Group member address"
                      autoCapitalize="none"
                      autoCorrect="off"
                    />
                    <DialogFooter>
                      <Button
                        type="submit"
                        disabled={!parseAccountAddress(groupMember) || groupUpdating}
                      >
                        {groupUpdating && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                        Invite member
                      </Button>
                    </DialogFooter>
                  </form>
                </DialogContent>
              </Dialog>
            )}
            <Button
              variant="ghost"
              size="icon"
              onClick={() => void service?.reconcile()}
              disabled={!service}
            >
              <RefreshCw className="h-4 w-4" />
              <span className="sr-only">{t('chat.sync')}</span>
            </Button>
            {!noteSelected &&
              selectedContact &&
              selectedContact.state !== 'pendingIncoming' &&
              selectedContact.state !== 'blocked' && (
              <Button
                variant="ghost"
                size="icon"
                onClick={() => void updateContact('block')}
                disabled={contactUpdating}
                aria-label={t('chat.requests.block')}
              >
                {contactUpdating
                  ? <Loader2 className="h-4 w-4 animate-spin" />
                  : <Ban className="h-4 w-4" />}
              </Button>
            )}
          </header>

          {error && (
            <div className="flex items-center gap-2 border-b border-destructive/20 bg-destructive-faint px-4 py-2 text-sm text-destructive">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span className="flex-1">{error}</span>
              {!service && !loading && (
                <Dialog open={deviceResetOpen} onOpenChange={setDeviceResetOpen}>
                  <DialogTrigger asChild>
                    <Button variant="outline" size="sm" className="shrink-0">
                      {t('chat.deviceRecovery.action')}
                    </Button>
                  </DialogTrigger>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>{t('chat.deviceRecovery.title')}</DialogTitle>
                      <DialogDescription>
                        {t('chat.deviceRecovery.description')}
                      </DialogDescription>
                    </DialogHeader>
                    <p className="text-sm text-destructive">
                      {t('chat.deviceRecovery.warning')}
                    </p>
                    <DialogFooter>
                      <Button
                        variant="outline"
                        onClick={() => setDeviceResetOpen(false)}
                        disabled={deviceResetting}
                      >
                        {t('common.cancel')}
                      </Button>
                      <Button
                        variant="destructive"
                        onClick={resetThisBrowserChatDevice}
                        disabled={deviceResetting}
                      >
                        {deviceResetting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                        {t('chat.deviceRecovery.confirm')}
                      </Button>
                    </DialogFooter>
                  </DialogContent>
                </Dialog>
              )}
            </div>
          )}
          {attention.length > 0 && (
            <div className="flex items-center gap-2 border-b border-warning/30 bg-warning-faint px-4 py-2 text-sm">
              <AlertTriangle className="h-4 w-4 text-warning" />
              {t('chat.attention', { count: attention.length })}
            </div>
          )}
          {requestSelected && (
            <div className="flex flex-wrap items-center gap-2 border-b border-warning/30 bg-warning-faint px-4 py-3 text-sm">
              <div className="min-w-0 flex-1">
                <p className="font-medium">{t('chat.requests.incoming', { peer: selectedTitle })}</p>
                <p className="text-xs text-muted-foreground">{t('chat.requests.description')}</p>
              </div>
              <Button size="sm" onClick={() => void updateContact('accept')} disabled={contactUpdating}>
                {t('chat.requests.accept')}
              </Button>
              <Button size="sm" variant="outline" onClick={() => void updateContact('reject')} disabled={contactUpdating}>
                {t('chat.requests.reject')}
              </Button>
              <Button size="sm" variant="destructive" onClick={() => void updateContact('block')} disabled={contactUpdating}>
                {t('chat.requests.block')}
              </Button>
            </div>
          )}
          {blockedSelected && (
            <div className="flex items-center gap-3 border-b border-destructive/20 bg-destructive-faint px-4 py-3 text-sm">
              <Ban className="h-4 w-4 text-destructive" />
              <span className="min-w-0 flex-1">{t('chat.requests.blocked', { peer: selectedTitle })}</span>
              <Button size="sm" variant="outline" onClick={() => void updateContact('unblock')} disabled={contactUpdating}>
                {t('chat.requests.unblock')}
              </Button>
            </div>
          )}

          <div className="flex-1 overflow-y-auto px-4 py-5 md:px-8">
            {!selectedConversation && (
              <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
                {t('chat.chooseConversation')}
              </div>
            )}
            <div className="mx-auto flex max-w-3xl flex-col gap-2">
              {messages.map((message) => (
                <MessageBubble
                  key={`${message.direction}:${message.id}`}
                  message={message}
                  newerClientLabel={t('chat.newerClient')}
                  accessToken={auth.accessToken ?? undefined}
                  mediaCache={mediaCache ?? undefined}
                  backupMediaCiphertext={service
                    ? (mediaId, accessToken, signal) => service.backupMediaCiphertext(
                        mediaId, accessToken, signal,
                      )
                    : undefined}
                  attachmentAccepted={!requestSelected && !blockedSelected}
                  repliedMessage={message.content.replyTo
                    ? messagesById.get(message.content.replyTo)
                    : undefined}
                  mutation={message.content.messageId
                    ? mutationsByMessageId.get(message.content.messageId)
                    : undefined}
                  repliedMessageMutation={message.content.replyTo
                    ? mutationsByMessageId.get(message.content.replyTo)
                    : undefined}
                  onReply={message.content.messageId
                    && !mutationsByMessageId.get(message.content.messageId)?.deleted
                    ? () => {
                        setEditingMessage(null)
                        setReplyingTo(message)
                      }
                    : undefined}
                  reactions={message.content.messageId
                    ? reactionsByMessageId.get(message.content.messageId)
                    : undefined}
                  reactionBusy={reactionSending}
                  selfAddress={selfAddress ?? undefined}
                  reactionProfiles={profilesByPeer}
                  onReact={message.content.messageId
                    && canSend
                    && !mutationsByMessageId.get(message.content.messageId)?.deleted
                    ? (emoji, active) => void toggleReaction(message, emoji, active)
                    : undefined}
                  onEdit={message.direction === 'outgoing'
                    && message.content.messageId
                    && message.content.text
                    && !mutationsByMessageId.get(message.content.messageId)?.deleted
                    ? () => beginEditing(message)
                    : undefined}
                  onDelete={message.direction === 'outgoing'
                    && message.content.messageId
                    && !mutationsByMessageId.get(message.content.messageId)?.deleted
                    ? () => void deleteMessage(message)
                    : undefined}
                  mutationBusy={mutationSending}
                  receipt={message.content.messageId
                    ? receiptsByMessageId.get(message.content.messageId)
                    : undefined}
                  nowMs={nowMs}
                  onVisible={startVisibleDisappearingMessage}
                  highlighted={highlightedSearchMessage === chatMessageDomKey(
                    message.direction,
                    message.id,
                  )}
                />
              ))}
              {typingLabel && (
                <div
                  className="px-3 py-1 text-xs text-muted-foreground"
                  aria-live="polite"
                  data-testid="chat-typing-indicator"
                >
                  {typingLabel}
                </div>
              )}
              <div ref={endRef} />
            </div>
          </div>

          <form className="border-t bg-card p-3 md:px-8" onSubmit={sendMessage}>
            {selectedGroupReadiness.blocksSending && (
              <div
                className="mx-auto mb-2 max-w-3xl rounded-md border border-warning/40 bg-warning/5 px-3 py-2 text-xs text-muted-foreground"
                data-testid="chat-group-delivery-readiness"
              >
                {selectedGroupReadiness.refused.length > 0
                  ? `Remove ${selectedGroupReadiness.refused.join(', ')} before sending; the invitation was rejected or expired.`
                  : `Waiting for ${selectedGroupReadiness.pending.join(', ')} to accept the encrypted group invitation.`}
              </div>
            )}
            {replyingTo && (
              <div
                className="mx-auto mb-2 flex max-w-3xl items-center gap-3 rounded-md border-l-4 border-primary bg-muted/50 px-3 py-2"
                data-testid="chat-reply-composer"
              >
                <Reply className="h-4 w-4 shrink-0 text-primary" />
                <span className="min-w-0 flex-1">
                  <span className="block text-xs font-medium">{t('chat.replies.replying')}</span>
                  <span className="block truncate text-xs text-muted-foreground">
                    {replyPreview(
                      replyingTo,
                      t('chat.newerClient'),
                      replyingTo.content.messageId
                        ? mutationsByMessageId.get(replyingTo.content.messageId)
                        : undefined,
                      t('chat.mutations.deleted'),
                    )}
                  </span>
                </span>
                <Button
                  type="button"
                  size="icon"
                  variant="ghost"
                  className="h-7 w-7"
                  onClick={() => setReplyingTo(null)}
                  aria-label={t('chat.replies.cancel')}
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>
            )}
            {editingMessage && (
              <div
                className="mx-auto mb-2 flex max-w-3xl items-center gap-3 rounded-md border-l-4 border-primary bg-muted/50 px-3 py-2"
                data-testid="chat-edit-composer"
              >
                <Pencil className="h-4 w-4 shrink-0 text-primary" />
                <span className="min-w-0 flex-1 text-xs font-medium">
                  {t('chat.mutations.editing')}
                </span>
                <Button
                  type="button"
                  size="icon"
                  variant="ghost"
                  className="h-7 w-7"
                  onClick={() => {
                    setEditingMessage(null)
                    setDraft('')
                  }}
                  aria-label={t('chat.mutations.cancelEdit')}
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>
            )}
            <div className="mx-auto flex max-w-3xl items-end gap-2">
              {capabilities.media && (
                <>
                  <input
                    ref={attachmentInputRef}
                    type="file"
                    className="hidden"
                    onChange={event => {
                      const file = event.target.files?.[0]
                      if (file) void sendAttachmentFile(file)
                    }}
                    data-testid="chat-attachment-input"
                  />
                  <input
                    ref={captureInputRef}
                    type="file"
                    accept="image/*,video/*"
                    capture="environment"
                    className="hidden"
                    onChange={event => {
                      const file = event.target.files?.[0]
                      if (file) void sendAttachmentFile(file)
                    }}
                    data-testid="chat-capture-input"
                  />
                  <Button
                    type="button"
                    size="icon"
                    variant="ghost"
                    disabled={!service || !canSendMedia || sending || voiceStarting || voiceRecording || voiceStopping}
                    onClick={() => attachmentInputRef.current?.click()}
                    aria-label={t('chat.attachments.send')}
                    data-testid="chat-attachment-button"
                  >
                    <Paperclip className="h-4 w-4" />
                  </Button>
                  <Button
                    type="button"
                    size="icon"
                    variant="ghost"
                    disabled={!service || !canSendMedia || sending || voiceStarting || voiceRecording || voiceStopping}
                    onClick={() => captureInputRef.current?.click()}
                    aria-label={t('chat.attachments.capture')}
                    data-testid="chat-capture-button"
                  >
                    <Camera className="h-4 w-4" />
                  </Button>
                  {voiceRecording ? (
                    <div
                      className="flex h-9 items-center gap-1 rounded-md border border-destructive/40 bg-destructive/5 px-1"
                      data-testid="chat-voice-recording"
                    >
                      <span className="ml-1 h-2 w-2 animate-pulse rounded-full bg-destructive" />
                      <span className="min-w-11 text-center font-mono text-xs">
                        {formatVoiceNoteElapsed(voiceElapsedMs)}
                      </span>
                      <Button
                        type="button"
                        size="icon"
                        variant="ghost"
                        className="h-7 w-7"
                        onClick={() => stopVoiceRecording(true)}
                        aria-label={t('chat.voice.cancel')}
                        data-testid="chat-voice-cancel"
                      >
                        <X className="h-4 w-4" />
                      </Button>
                      <Button
                        type="button"
                        size="icon"
                        variant="ghost"
                        className="h-7 w-7 text-destructive"
                        onClick={() => stopVoiceRecording(false)}
                        aria-label={t('chat.voice.stop')}
                        data-testid="chat-voice-stop"
                      >
                        <Square className="h-3.5 w-3.5 fill-current" />
                      </Button>
                    </div>
                  ) : (
                    <Button
                      type="button"
                      size="icon"
                      variant="ghost"
                      disabled={!service || !canSendMedia || sending || voiceStarting || voiceStopping}
                      onClick={() => void startVoiceRecording()}
                      aria-label={t('chat.voice.start')}
                      data-testid="chat-voice-button"
                    >
                      {voiceStarting || voiceStopping
                        ? <Loader2 className="h-4 w-4 animate-spin" />
                        : <Mic className="h-4 w-4" />}
                    </Button>
                  )}
                </>
              )}
              <Input
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
                placeholder={
                  requestSelected
                    ? t('chat.requests.acceptBeforeReply')
                    : blockedSelected
                      ? t('chat.requests.unblockBeforeReply')
                      : selectedGroup && !selectedGroupCanSend
                        ? 'Only group administrators may send messages'
                      : selectedGroupReadiness.refused.length > 0
                        ? 'Remove members who rejected or missed the invitation'
                      : selectedGroupReadiness.pending.length > 0
                        ? 'Waiting for invited members to accept'
                      : selectedGroupClosed
                        ? 'This MLS group is closed'
                      : selectedRestoredHistoryGroup
                        ? 'Protected MLS history is read-only on this device'
                      : selectedConversation
                    ? t('chat.messagePeer', {
                        peer: selectedTitle,
                      })
                    : t('chat.selectConversation')
                }
                disabled={!service || !canSend || sending || mutationSending || voiceRecording || voiceStopping}
                maxLength={16_000}
                autoComplete="off"
              />
              <Button type="submit" size="icon" disabled={!draft.trim() || !service || !canSend || sending || mutationSending || voiceRecording || voiceStopping}>
                {sending || mutationSending
                  ? <Loader2 className="h-4 w-4 animate-spin" />
                  : editingMessage
                    ? <Check className="h-4 w-4" />
                    : <Send className="h-4 w-4" />}
                <span className="sr-only">{t('chat.send')}</span>
              </Button>
            </div>
          </form>
        </main>
      )}
    </div>
  )
}

type AvatarProfile = Pick<ChatProfile, 'displayName' | 'avatar' | 'avatarContentType'>

function ProfileAvatar({
  profile,
  address,
  className,
}: {
  profile?: AvatarProfile | null
  address: string
  className?: string
}) {
  const source = profile?.avatar && profile.avatarContentType
    ? `data:${profile.avatarContentType};base64,${profile.avatar}`
    : null
  const initial = (profile?.displayName || address).trim().slice(0, 1).toUpperCase() || '?'
  return (
    <span
      className={cn(
        'flex shrink-0 items-center justify-center overflow-hidden rounded-full font-semibold',
        className,
      )}
      aria-hidden="true"
    >
      {source
        ? <img src={source} alt="" className="h-full w-full object-cover" />
        : initial}
    </span>
  )
}

function ProfileEditor({
  profile,
  address,
  disabled,
  onSave,
}: {
  profile: ChatProfile | null
  address: string
  disabled: boolean
  onSave: (displayName: string, avatar?: string, avatarContentType?: string) => Promise<void>
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [displayName, setDisplayName] = useState('')
  const [avatar, setAvatar] = useState<string | undefined>()
  const [avatarContentType, setAvatarContentType] = useState<string | undefined>()
  const [avatarProcessing, setAvatarProcessing] = useState(false)
  const [saving, setSaving] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  function changeOpen(next: boolean) {
    if (next) {
      setDisplayName(profile?.displayName ?? '')
      setAvatar(profile?.avatar)
      setAvatarContentType(profile?.avatarContentType)
    }
    setOpen(next)
  }

  async function chooseAvatar(file: File | undefined) {
    if (!file) return
    setAvatarProcessing(true)
    try {
      const normalized = await normalizeAvatar(file)
      setAvatar(normalized.base64)
      setAvatarContentType(normalized.contentType)
    } catch {
      toast.error(t('chat.profile.avatarError'))
    } finally {
      setAvatarProcessing(false)
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!displayName.trim() || saving || avatarProcessing) return
    setSaving(true)
    try {
      await onSave(displayName.trim(), avatar, avatarContentType)
      setOpen(false)
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setSaving(false)
    }
  }

  const preview: AvatarProfile = { displayName, avatar, avatarContentType }
  return (
    <Dialog open={open} onOpenChange={changeOpen}>
      <DialogTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="shrink-0 rounded-full"
          disabled={disabled || !profile}
          aria-label={t('chat.profile.open')}
        >
          <ProfileAvatar
            profile={profile}
            address={address}
            className="h-9 w-9 bg-primary/15 text-primary"
          />
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <form className="grid gap-5" onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>{t('chat.profile.title')}</DialogTitle>
            <DialogDescription>{t('chat.profile.description')}</DialogDescription>
          </DialogHeader>
          <div className="flex flex-col items-center gap-3">
            <ProfileAvatar
              profile={preview}
              address={address}
              className="h-24 w-24 bg-primary/15 text-2xl text-primary"
            />
            <input
              ref={fileRef}
              type="file"
              accept="image/png,image/jpeg,image/webp"
              className="hidden"
              onChange={(event) => void chooseAvatar(event.target.files?.[0])}
            />
            <div className="flex flex-wrap justify-center gap-2">
              <Button
                type="button"
                size="sm"
                variant="outline"
                disabled={avatarProcessing || saving}
                onClick={() => fileRef.current?.click()}
              >
                {avatarProcessing
                  ? <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  : <Camera className="mr-2 h-4 w-4" />}
                {t('chat.profile.changeAvatar')}
              </Button>
              {avatar && (
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  disabled={saving}
                  onClick={() => {
                    setAvatar(undefined)
                    setAvatarContentType(undefined)
                  }}
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  {t('chat.profile.removeAvatar')}
                </Button>
              )}
            </div>
            <p className="text-center text-xs text-muted-foreground">
              {t('chat.profile.avatarHint')}
            </p>
          </div>
          <label className="grid gap-2 text-sm font-medium">
            {t('chat.profile.displayName')}
            <Input
              value={displayName}
              onChange={(event) => setDisplayName(event.target.value)}
              maxLength={80}
              required
              autoComplete="name"
            />
          </label>
          <div className="rounded-lg border bg-muted/40 px-3 py-2.5">
            <p className="text-xs font-medium">{t('chat.profile.address')}</p>
            <code className="mt-1 block break-all text-xs text-muted-foreground">{address}</code>
          </div>
          <p className="text-xs text-muted-foreground">{t('chat.profile.visibility')}</p>
          <DialogFooter>
            <Button type="submit" disabled={!displayName.trim() || saving || avatarProcessing}>
              {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {t('common.save')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function MessageBubble({
  message,
  newerClientLabel,
  accessToken,
  mediaCache,
  backupMediaCiphertext,
  attachmentAccepted = true,
  repliedMessage,
  repliedMessageMutation,
  mutation,
  onReply,
  reactions = [],
  reactionBusy,
  selfAddress,
  reactionProfiles,
  onReact,
  onEdit,
  onDelete,
  mutationBusy,
  receipt,
  nowMs,
  onVisible,
  highlighted,
}: {
  message: ChatHistoryEntry
  newerClientLabel: string
  accessToken?: string
  mediaCache?: PrivateCiphertextCacheV1
  backupMediaCiphertext?: (
    mediaId: string,
    accessToken: string,
    signal: AbortSignal,
  ) => AsyncIterable<Uint8Array>
  attachmentAccepted?: boolean
  repliedMessage?: ChatHistoryEntry
  repliedMessageMutation?: MessageMutationState
  mutation?: MessageMutationState
  onReply?: () => void
  reactions?: ReactionAggregate[]
  reactionBusy?: string | null
  selfAddress?: string
  reactionProfiles?: ReadonlyMap<string, PeerChatProfile>
  onReact?: (emoji: ChatReactionEmoji, active: boolean) => void
  onEdit?: () => void
  onDelete?: () => void
  mutationBusy?: boolean
  receipt?: MessageReceiptState
  nowMs: number
  onVisible?: (message: ChatHistoryEntry) => void
  highlighted?: boolean
}) {
  const { t } = useTranslation()
  const outgoing = message.direction === 'outgoing'
  const [cacheState, setCacheState] = useState<ChatAttachmentCacheState>('checking')
  const [downloadProgress, setDownloadProgress] = useState(0)
  const [saving, setSaving] = useState(false)
  const [viewerOpen, setViewerOpen] = useState(false)
  const downloadControllerRef = useRef<AbortController | null>(null)
  const bubbleRef = useRef<HTMLDivElement>(null)
  const attachment = message.content.attachment
  const attachmentSuite = attachment?.suite
  const attachmentId = attachment?.attachmentId
  const attachmentCiphertextBytes = attachment?.ciphertextBytes
  const attachmentCiphertextSha256 = attachment?.ciphertextSha256
  const attachmentCacheBinding = useMemo(() => {
    if (attachmentSuite === undefined || !attachmentId ||
        attachmentCiphertextBytes === undefined || !attachmentCiphertextSha256) return undefined
    return {
      product: 'chat' as const,
      suite: attachmentSuite,
      objectId: attachmentId,
      ciphertextBytes: attachmentCiphertextBytes,
      ciphertextSha256: attachmentCiphertextSha256,
    }
  }, [
    attachmentCiphertextBytes,
    attachmentCiphertextSha256,
    attachmentId,
    attachmentSuite,
  ])
  const expiresAtMs = disappearingMessageExpiresAt(message)
  const selectedReaction = reactions.find(reaction => reaction.reactedBySelf)?.emoji
  const viewerKind = attachment ? chatMediaViewerKindV1(attachment) : null

  async function ensureAttachmentAvailable(): Promise<void> {
    if (!attachmentAccepted || !attachment || !mediaCache) {
      throw new Error('attachment is not available')
    }
    if (cacheState === 'available' || await isChatMediaAvailableInKutupV1(mediaCache, attachment)) {
      setCacheState('available')
      return
    }
    if (!accessToken) throw new Error('sign in again to download this attachment')
    const controller = new AbortController()
    downloadControllerRef.current = controller
    setCacheState('downloading')
    setDownloadProgress(0)
    try {
      await downloadChatMediaToCacheV1(
        mediaCache,
        attachment,
        accessToken,
        (received, total) => setDownloadProgress(Math.floor(received / total * 100)),
        controller.signal,
        expiresAtMs === undefined ? {} : { expiresAtMs },
        attachment.backupMediaId && backupMediaCiphertext
          ? () => backupMediaCiphertext(
              attachment.backupMediaId!, accessToken, controller.signal,
            )
          : undefined,
      )
      setCacheState('available')
    } catch (cause) {
      setCacheState('remote')
      throw cause
    } finally {
      downloadControllerRef.current = null
    }
  }

  function activateAttachment(): void {
    if (cacheState === 'available' && viewerKind) setViewerOpen(true)
  }

  useEffect(() => {
    let cancelled = false
    downloadControllerRef.current?.abort()
    setDownloadProgress(0)
    if (!attachmentCacheBinding || !mediaCache) {
      setCacheState('remote')
      return
    }
    setCacheState('checking')
    void mediaCache.getVerified(attachmentCacheBinding)
      .then(available => {
        if (!cancelled) setCacheState(available !== null ? 'available' : 'remote')
      })
      .catch(() => { if (!cancelled) setCacheState('remote') })
    return () => {
      cancelled = true
      downloadControllerRef.current?.abort()
    }
  }, [attachmentCacheBinding, mediaCache])

  useEffect(() => {
    if (!attachmentCacheBinding || !mediaCache || !mutation?.deleted) return
    setViewerOpen(false)
    setCacheState('remote')
    void mediaCache.remove(attachmentCacheBinding).catch(() => undefined)
  }, [attachmentCacheBinding, mediaCache, mutation?.deleted])

  useEffect(() => {
    if (attachmentAccepted) return
    downloadControllerRef.current?.abort()
    setViewerOpen(false)
  }, [attachmentAccepted])

  useEffect(() => {
    if (!attachmentCacheBinding || !mediaCache || expiresAtMs === undefined || expiresAtMs > nowMs) return
    downloadControllerRef.current?.abort()
    setViewerOpen(false)
    setCacheState('remote')
    void mediaCache.remove(attachmentCacheBinding).catch(() => undefined)
  }, [attachmentCacheBinding, expiresAtMs, mediaCache, nowMs])
  useEffect(() => {
    const element = bubbleRef.current
    if (!element || !onVisible || typeof IntersectionObserver === 'undefined') return
    const observer = new IntersectionObserver(entries => {
      if (entries.some(entry => entry.isIntersecting)) onVisible(message)
    }, { threshold: 0.1 })
    observer.observe(element)
    return () => observer.disconnect()
  }, [message, onVisible])
  return (
    <div
      id={chatMessageDomKey(message.direction, message.id)}
      ref={bubbleRef}
      className={cn(
        'group flex items-center gap-1 rounded-xl transition-shadow',
        outgoing ? 'justify-end' : 'justify-start',
        highlighted && 'ring-2 ring-primary ring-offset-2 ring-offset-background',
      )}
      data-testid="chat-message"
    >
      {outgoing && (
        <MessageActions
          onReply={onReply}
          onReact={onReact}
          reactionBusy={reactionBusy}
          selectedReaction={selectedReaction}
          onEdit={onEdit}
          onDelete={onDelete}
          mutationBusy={mutationBusy}
        />
      )}
      <div
        className={cn(
          'flex min-w-0 max-w-[82%] flex-col md:max-w-[70%]',
          outgoing ? 'items-end' : 'items-start',
        )}
      >
        <div
          className={cn(
            'relative min-w-0 max-w-full rounded-2xl px-3.5 py-2 shadow-sm',
            outgoing
              ? 'rounded-br-md bg-primary text-primary-foreground'
              : 'rounded-bl-md border bg-card',
          )}
        >
        {message.content.replyTo && (
          <div
            className={cn(
              'mb-2 max-w-full rounded-md border-l-2 px-2 py-1 text-xs',
              outgoing
                ? 'border-primary-foreground/60 bg-primary-foreground/10'
                : 'border-primary bg-muted/70',
            )}
            data-testid="chat-reply-context"
          >
            <span className="block truncate">
              {repliedMessage
                ? replyPreview(repliedMessage, newerClientLabel, repliedMessageMutation, t('chat.mutations.deleted'))
                : t('chat.replies.unavailable')}
            </span>
          </div>
        )}
        {mutation?.deleted ? (
          <p className="text-sm italic opacity-75" data-testid="chat-message-deleted">
            {t('chat.mutations.deleted')}
          </p>
        ) : attachment ? (
          <div className="min-w-52">
            {attachment.mediaClass !== 'audio' && attachment.preview && (
              <ChatAttachmentPreview
                attachment={attachment}
                visible={attachmentAccepted}
                className="mb-2"
                onActivate={() => {
                  if (cacheState === 'remote') {
                    void ensureAttachmentAvailable().catch(cause => {
                      if (!(cause instanceof DOMException && cause.name === 'AbortError')) {
                        toast.error('Encrypted attachment download failed')
                      }
                    })
                  } else {
                    activateAttachment()
                  }
                }}
                activationLabel={cacheState === 'remote'
                  ? `Download ${attachment.filename} into Kutup`
                  : `Open ${attachment.filename}`}
                activationMode={cacheState === 'remote' ? 'download' : 'open'}
                disabled={!attachmentAccepted || !mediaCache || cacheState === 'checking' ||
                  cacheState === 'downloading' || cacheState === 'remote' && !accessToken ||
                  cacheState === 'available' && !viewerKind}
              />
            )}
            <div className="flex items-center gap-3">
              {attachment.mediaClass === 'audio' && mediaCache ? (
                <ChatVoiceNotePlayer
                  cache={mediaCache}
                  attachment={attachment}
                  downloadState={cacheState}
                  downloadProgress={downloadProgress}
                  disabled={!attachmentAccepted || cacheState === 'checking' ||
                    cacheState === 'remote' && !accessToken}
                  onDownload={ensureAttachmentAvailable}
                  onCancel={() => downloadControllerRef.current?.abort()}
                  onError={() => toast.error('Voice note could not be played')}
                />
              ) : (
                <FileText className="h-7 w-7 shrink-0" />
              )}
              {attachment.mediaClass !== 'audio' && <span className="min-w-0 flex-1">
                <span className="block truncate text-sm font-medium">{attachment.filename}</span>
                <span className={cn(
                  'block text-[11px]',
                  outgoing ? 'text-primary-foreground/70' : 'text-muted-foreground',
                )}>
                  {formatBytes(attachment.plaintextBytes)} · {
                    cacheState === 'available'
                      ? 'available in Kutup'
                      : cacheState === 'downloading'
                        ? `${downloadProgress}% downloaded`
                        : 'encrypted'
                  }
                </span>
              </span>}
              {attachment.mediaClass !== 'audio' && (
                <ChatAttachmentAction
                  attachment={attachment}
                  cacheState={cacheState}
                  downloadProgress={downloadProgress}
                  viewerKind={viewerKind}
                  outgoing={outgoing}
                  disabled={!attachmentAccepted || !mediaCache || cacheState === 'remote' && !accessToken}
                  onDownload={ensureAttachmentAvailable}
                  onCancel={() => downloadControllerRef.current?.abort()}
                  onOpen={activateAttachment}
                  onError={() => toast.error('Encrypted attachment download failed')}
                />
              )}
              {attachmentAccepted && cacheState === 'available' && mediaCache && (
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button
                      type="button"
                      size="icon"
                      variant={outgoing ? 'secondary' : 'ghost'}
                      className="h-8 w-8 shrink-0"
                      aria-label={`More actions for ${attachment.filename}`}
                    >
                      {saving
                  ? <Loader2 className="h-4 w-4 animate-spin" />
                        : <MoreVertical className="h-4 w-4" />}
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem
                      disabled={saving}
                      onSelect={() => {
                        setSaving(true)
                        void saveCachedChatMediaToDeviceV1(mediaCache, attachment)
                          .catch(cause => {
                            if (!(cause instanceof DOMException && cause.name === 'AbortError')) {
                              toast.error('Attachment could not be saved to this device')
                            }
                          })
                          .finally(() => setSaving(false))
                      }}
                    >
                      <Download className="mr-2 h-4 w-4" />
                      Save to device
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      onSelect={() => {
                        setViewerOpen(false)
                        void clearCachedChatMediaV1(mediaCache, attachment)
                          .then(() => setCacheState('remote'))
                          .catch(() => toast.error('Local encrypted copy could not be cleared'))
                      }}
                    >
                      <Trash2 className="mr-2 h-4 w-4" />
                      Clear local copy
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              )}
            </div>
            {mediaCache && (
              <ChatAttachmentViewer
                open={viewerOpen}
                onOpenChange={setViewerOpen}
                cache={mediaCache}
                attachment={attachment}
              />
            )}
          </div>
        ) : (
          <p className="whitespace-pre-wrap break-words text-sm">
            {mutation?.editedText ?? message.content.text ?? newerClientLabel}
          </p>
        )}
        <span
          className={cn(
            'mt-1 flex items-center justify-end gap-1 text-[10px]',
            outgoing ? 'text-primary-foreground/70' : 'text-muted-foreground',
          )}
        >
          {formatTime(message.content.sentAt)}
          {mutation?.editedText && !mutation.deleted && (
            <span data-testid="chat-message-edited">· {t('chat.mutations.edited')}</span>
          )}
          {expiresAtMs !== undefined && (
            <span
              className="flex items-center gap-0.5"
              title={t('chat.disappearing.expires', {
                time: formatRemainingTime(expiresAtMs - nowMs),
              })}
              data-testid="chat-message-expiry"
            >
              <Timer className="h-3 w-3" />
              {formatRemainingTime(expiresAtMs - nowMs)}
            </span>
          )}
          {outgoing && receipt?.read ? (
            <span
              className="flex items-center gap-0.5 font-medium"
              title={t('chat.receipts.readBy', { count: receipt.read })}
              aria-label={t('chat.receipts.readBy', { count: receipt.read })}
              data-testid="chat-receipt-read"
            >
              <CheckCheck className="h-3 w-3" />
              {receipt.read > 1 && receipt.read}
            </span>
          ) : outgoing && receipt?.delivered ? (
            <span
              className="flex items-center gap-0.5"
              title={t('chat.receipts.deliveredTo', { count: receipt.delivered })}
              aria-label={t('chat.receipts.deliveredTo', { count: receipt.delivered })}
              data-testid="chat-receipt-delivered"
            >
              <CheckCheck className="h-3 w-3" />
              {receipt.delivered > 1 && receipt.delivered}
            </span>
          ) : outgoing && message.delivered ? (
            <Check className="h-3 w-3" aria-label={t('chat.receipts.sent')} />
          ) : null}
        </span>
        </div>
        {!mutation?.deleted && reactions.length > 0 && (
          <MessageReactionRow
            reactions={reactions}
            outgoing={outgoing}
            selfAddress={selfAddress}
            reactionProfiles={reactionProfiles}
            reactionBusy={reactionBusy}
            onReact={onReact}
          />
        )}
      </div>
      {!outgoing && (
        <MessageActions
          onReply={onReply}
          onReact={onReact}
          reactionBusy={reactionBusy}
          selectedReaction={selectedReaction}
        />
      )}
    </div>
  )
}

function MessageReactionRow({
  reactions,
  outgoing,
  selfAddress,
  reactionProfiles,
  reactionBusy,
  onReact,
}: {
  reactions: ReactionAggregate[]
  outgoing: boolean
  selfAddress?: string
  reactionProfiles?: ReadonlyMap<string, PeerChatProfile>
  reactionBusy?: string | null
  onReact?: (emoji: ChatReactionEmoji, active: boolean) => void
}) {
  const { t } = useTranslation()
  return (
    <div
      className={cn(
        'z-10 -mt-1 flex min-h-[22px] max-w-full flex-wrap gap-1 px-2',
        outgoing ? 'justify-end' : 'justify-start',
      )}
      data-testid="chat-reactions"
    >
      {reactions.map(reaction => (
        <DropdownMenu key={reaction.emoji}>
          <DropdownMenuTrigger asChild>
            <button
              type="button"
              className={cn(
                'flex h-[22px] min-w-7 items-center justify-center gap-1 rounded-full border border-border bg-muted px-1.5 text-xs text-foreground outline-none transition-colors hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring',
                reaction.reactedBySelf && 'border-primary bg-primary text-primary-foreground hover:bg-primary/90',
              )}
              aria-label={t('chat.reactions.details', {
                emoji: reaction.emoji,
                count: reaction.count,
              })}
              data-testid="chat-reaction-aggregate"
              data-emoji={reaction.emoji}
              data-count={reaction.count}
            >
              <span>{reaction.emoji}</span>
              {reaction.count > 1 && <span className="font-semibold tabular-nums">{reaction.count}</span>}
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align={outgoing ? 'end' : 'start'} className="min-w-56">
            <div className="border-b px-2 py-1.5 text-xs font-medium text-muted-foreground">
              {reaction.emoji} {t('chat.reactions.reactedWith')}
            </div>
            {reaction.reactors.map(reactor => {
              const isSelf = reactor === selfAddress
              const label = isSelf
                ? t('chat.reactions.you')
                : reactionProfiles?.get(reactor)?.displayName || reactor
              if (isSelf && reaction.reactedBySelf && onReact) {
                return (
                  <DropdownMenuItem
                    key={reactor}
                    disabled={reactionBusy !== null && reactionBusy !== undefined}
                    onSelect={() => onReact(reaction.emoji, false)}
                  >
                    <span className="min-w-0 flex-1 truncate">{label}</span>
                    <span className="text-xs text-muted-foreground">
                      {t('chat.reactions.removeMine')}
                    </span>
                  </DropdownMenuItem>
                )
              }
              return (
                <div key={reactor} className="truncate px-2 py-1.5 text-sm">
                  {label}
                </div>
              )
            })}
          </DropdownMenuContent>
        </DropdownMenu>
      ))}
    </div>
  )
}

function MessageActions({
  onReply,
  onReact,
  reactionBusy,
  selectedReaction,
  onEdit,
  onDelete,
  mutationBusy,
}: {
  onReply?: () => void
  onReact?: (emoji: ChatReactionEmoji, active: boolean) => void
  reactionBusy?: string | null
  selectedReaction?: ChatReactionEmoji
  onEdit?: () => void
  onDelete?: () => void
  mutationBusy?: boolean
}) {
  const { t } = useTranslation()
  if (!onReply && !onReact && !onEdit && !onDelete) return null
  return (
    <span className="flex shrink-0 items-center">
      {onReact && (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              type="button"
              size="icon"
              variant="ghost"
              className="h-7 w-7 opacity-70 md:opacity-0 md:transition-opacity md:group-hover:opacity-100 md:focus-visible:opacity-100"
              disabled={reactionBusy !== null && reactionBusy !== undefined}
              aria-label={t('chat.reactions.add')}
              data-testid="chat-reaction-button"
            >
              <SmilePlus className="h-3.5 w-3.5" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="min-w-0 rounded-xl p-1.5" data-testid="chat-reaction-picker">
            <div className="flex gap-0.5">
              {CHAT_REACTION_EMOJIS.map(emoji => (
                <DropdownMenuItem
                  key={emoji}
                  className={cn(
                    'h-9 w-9 cursor-pointer justify-center rounded-lg p-0 text-xl',
                    selectedReaction === emoji && 'bg-primary text-primary-foreground focus:bg-primary focus:text-primary-foreground',
                  )}
                  onSelect={() => onReact(emoji, selectedReaction !== emoji)}
                  aria-label={selectedReaction === emoji
                    ? `${emoji} ${t('chat.reactions.removeMine')}`
                    : t('chat.reactions.addEmoji', { emoji })}
                  aria-pressed={selectedReaction === emoji}
                  data-emoji={emoji}
                >
                  {emoji}
                </DropdownMenuItem>
              ))}
            </div>
          </DropdownMenuContent>
        </DropdownMenu>
      )}
      {onEdit && (
        <Button
          type="button"
          size="icon"
          variant="ghost"
          className="h-7 w-7 opacity-70 md:opacity-0 md:transition-opacity md:group-hover:opacity-100 md:focus-visible:opacity-100"
          disabled={mutationBusy}
          onClick={onEdit}
          aria-label={t('chat.mutations.edit')}
          data-testid="chat-edit-button"
        >
          <Pencil className="h-3.5 w-3.5" />
        </Button>
      )}
      {onDelete && (
        <Button
          type="button"
          size="icon"
          variant="ghost"
          className="h-7 w-7 opacity-70 md:opacity-0 md:transition-opacity md:group-hover:opacity-100 md:focus-visible:opacity-100"
          disabled={mutationBusy}
          onClick={onDelete}
          aria-label={t('chat.mutations.delete')}
          data-testid="chat-delete-button"
        >
          <Trash2 className="h-3.5 w-3.5" />
        </Button>
      )}
      {onReply && <ReplyButton onReply={onReply} label={t('chat.replies.reply')} />}
    </span>
  )
}

function ReplyButton({ onReply, label }: { onReply: () => void; label: string }) {
  return (
    <Button
      type="button"
      size="icon"
      variant="ghost"
      className="h-7 w-7 shrink-0 opacity-70 md:opacity-0 md:transition-opacity md:group-hover:opacity-100 md:focus-visible:opacity-100"
      onClick={onReply}
      aria-label={label}
      data-testid="chat-reply-button"
    >
      <Reply className="h-3.5 w-3.5" />
    </Button>
  )
}

function replyPreview(
  message: ChatHistoryEntry,
  newerClientLabel: string,
  mutation?: MessageMutationState,
  deletedLabel = newerClientLabel,
): string {
  if (mutation?.deleted) return deletedLabel
  return mutation?.editedText
    ?? message.content.text
    ?? message.content.attachment?.filename
    ?? newerClientLabel
}

function chatMessageDomKey(direction: ChatHistoryEntry['direction'], messageId: string): string {
  return `chat-message-${direction}-${messageId}`
}

function compareContentOperations(left: ChatHistoryEntry, right: ChatHistoryEntry): number {
  if (left.timestampMs !== right.timestampMs) return left.timestampMs - right.timestampMs
  const sequence = compareDecimalStrings(left.content.seq, right.content.seq)
  if (sequence !== 0) return sequence
  const device = (left.senderDeviceId ?? 0) - (right.senderDeviceId ?? 0)
  return device !== 0 ? device : left.id.localeCompare(right.id)
}

function disappearingPresetLabel(seconds: number, t: TFunction): string {
  const preset = DISAPPEARING_PRESETS.find(option => option.durationSeconds === seconds)
  return preset ? t(`chat.disappearing.presets.${preset.key}`) : formatRemainingTime(seconds * 1_000)
}

function messageActor(
  message: ChatHistoryEntry,
  conversation: ConversationId,
  selfAddress: string,
): string | null {
  if (message.direction === 'outgoing') return selfAddress
  return conversation.kind === 'direct' ? directAddress(conversation) : message.peer
}

function compareDecimalStrings(left: string, right: string): number {
  const normalizedLeft = left.replace(/^0+(?=\d)/u, '')
  const normalizedRight = right.replace(/^0+(?=\d)/u, '')
  if (normalizedLeft.length !== normalizedRight.length) {
    return normalizedLeft.length - normalizedRight.length
  }
  return normalizedLeft.localeCompare(normalizedRight)
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  const units = ['KiB', 'MiB', 'GiB']
  let value = bytes
  let unit = -1
  do {
    value /= 1024
    unit += 1
  } while (value >= 1024 && unit < units.length - 1)
  return `${value >= 10 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`
}

function backupStatusLabel(status: ChatBackupView | null, t: TFunction): string {
  switch (status?.state) {
    case 'protected': return t('chat.backup.status.protected')
    case 'backingUp': return t('chat.backup.status.backingUp')
    case 'offline': return t('chat.backup.status.offline')
    case 'mediaPending': return t('chat.backup.status.mediaPending')
    case 'needsAttention': return t('chat.backup.status.needsAttention')
    default: return t('chat.backup.status.starting')
  }
}

const MAX_PROFILE_AVATAR_BYTES = 512 * 1024

async function normalizeAvatar(file: File): Promise<{ base64: string; contentType: string }> {
  if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type)) {
    throw new Error('unsupported avatar type')
  }
  const image = await loadImage(file)
  const sourceSize = Math.min(image.naturalWidth, image.naturalHeight)
  if (sourceSize < 1) throw new Error('empty avatar')
  const outputSize = Math.min(512, sourceSize)
  const canvas = document.createElement('canvas')
  canvas.width = outputSize
  canvas.height = outputSize
  const context = canvas.getContext('2d')
  if (!context) throw new Error('avatar canvas is unavailable')
  const sourceX = (image.naturalWidth - sourceSize) / 2
  const sourceY = (image.naturalHeight - sourceSize) / 2
  context.drawImage(
    image,
    sourceX,
    sourceY,
    sourceSize,
    sourceSize,
    0,
    0,
    outputSize,
    outputSize,
  )

  let blob: Blob | null = null
  for (const quality of [0.86, 0.72, 0.56]) {
    blob = await canvasToBlob(canvas, 'image/webp', quality)
    if (blob && blob.size <= MAX_PROFILE_AVATAR_BYTES) break
  }
  if (!blob || blob.size > MAX_PROFILE_AVATAR_BYTES || blob.type !== 'image/webp') {
    throw new Error('avatar could not be normalized')
  }
  return {
    base64: bytesToBase64(new Uint8Array(await blob.arrayBuffer())),
    contentType: blob.type,
  }
}

function loadImage(file: File): Promise<HTMLImageElement> {
  const url = URL.createObjectURL(file)
  return new Promise((resolve, reject) => {
    const image = new Image()
    image.onload = () => {
      URL.revokeObjectURL(url)
      resolve(image)
    }
    image.onerror = () => {
      URL.revokeObjectURL(url)
      reject(new Error('avatar image could not be read'))
    }
    image.src = url
  })
}

function canvasToBlob(canvas: HTMLCanvasElement, type: string, quality: number): Promise<Blob | null> {
  return new Promise((resolve) => canvas.toBlob(resolve, type, quality))
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = ''
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000))
  }
  return btoa(binary)
}

function formatTime(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' }).format(date)
}

function formatDeviceTime(value?: string | null): string {
  if (!value) return ''
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date)
}

function errorMessage(
  error: unknown,
  t: (key: string, options?: Record<string, unknown>) => string,
): string {
  if (error instanceof ChatServiceError) return t(`chat.errors.${error.code}`)
  if (error instanceof MlsSendError) return error.message
  if (error instanceof Error && error.message.startsWith('MLS ')) return error.message
  return t('chat.errors.unavailable')
}
