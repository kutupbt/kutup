import { FormEvent, useEffect, useMemo, useRef, useState } from 'react'
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
  MonitorSmartphone,
  Plus,
  Paperclip,
  Pencil,
  QrCode,
  RefreshCw,
  Reply,
  Send,
  Shield,
  ShieldCheck,
  SmilePlus,
  Trash2,
  UserMinus,
  Users,
  X,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
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
import { MlsSendError } from '@/chat/mls-service'
import { MlsGroupSecurityDetails } from '@/chat/MlsGroupSecurityDetails'
import { SafetyVerificationDialog } from '@/chat/SafetyVerificationDialog'
import { mlsGroupInvitationReadiness } from '@/chat/group-readiness'
import { isSupportedChat, useChatCapabilities } from '@/chat/capabilities'
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
  ChatHistoryTransferSummary,
  ChatProfile,
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
  ChatReactionV1,
  ChatMessageMutationV1,
} from '@/chat/types'
import { cn } from '@/lib/utils'
import { copyText } from '@/lib/format'
import { downloadChatMediaV1, uploadChatMediaV1 } from '@/chat/media'

const CHAT_REACTION_EMOJIS = ['👍', '❤️', '😂', '😮', '😢', '🙏'] as const
type ChatReactionEmoji = ChatReactionV1['emoji']

interface ReactionAggregate {
  emoji: ChatReactionEmoji
  count: number
  reactedBySelf: boolean
}

interface MessageMutationState {
  editedText?: string
  deleted: boolean
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
  const [draft, setDraft] = useState('')
  const [replyingTo, setReplyingTo] = useState<ChatHistoryEntry | null>(null)
  const [editingMessage, setEditingMessage] = useState<ChatHistoryEntry | null>(null)
  const [loading, setLoading] = useState(true)
  const [sending, setSending] = useState(false)
  const [reactionSending, setReactionSending] = useState<string | null>(null)
  const [mutationSending, setMutationSending] = useState(false)
  const [readReceiptsEnabled, setReadReceiptsEnabled] = useState(() =>
    window.localStorage.getItem('kutup:chat:read-receipts') === '1')
  const [pageVisible, setPageVisible] = useState(() => document.visibilityState === 'visible')
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
  const [devicesOpen, setDevicesOpen] = useState(false)
  const [devices, setDevices] = useState<ChatDevice[]>([])
  const [devicesLoading, setDevicesLoading] = useState(false)
  const [deviceRevoking, setDeviceRevoking] = useState<number | null>(null)
  const [historyTransfers, setHistoryTransfers] = useState<ChatHistoryTransferSummary[]>([])
  const [historyTransferBusy, setHistoryTransferBusy] = useState<string | null>(null)
  const [mediaStorageOpen, setMediaStorageOpen] = useState(false)
  const [mediaStorage, setMediaStorage] = useState<ChatMediaStorageView | null>(null)
  const [mediaStorageLoading, setMediaStorageLoading] = useState(false)
  const [mediaStorageClearing, setMediaStorageClearing] = useState<string | null>(null)
  const endRef = useRef<HTMLDivElement>(null)
  const attachmentInputRef = useRef<HTMLInputElement>(null)
  const historyRefreshGeneration = useRef(0)
  const receiptAttempted = useRef(new Set<string>())
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
          setError(null)
        }
      } catch (cause) {
        if (!cancelled) setError(errorMessage(cause, t))
      }
    }

    ChatService.open({
      userId: auth.userId,
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
  }, [auth.userId, auth.username, capabilities, masterKey, t])

  const contactsByPeer = useMemo(
    () => new Map(contacts.map((contact) => [contact.peer, contact])),
    [contacts],
  )
  const profilesByPeer = useMemo(
    () => new Map(peerProfiles.map((profile) => [profile.peer, profile])),
    [peerProfiles],
  )

  const visibleHistory = useMemo(
    () => history.filter(message =>
      !message.content.reaction && !message.content.mutation && !message.content.receipt),
    [history],
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
    }
  }, [groups, peers, selectedConversation])

  const selectedKey = selectedConversation ? conversationKey(selectedConversation) : null
  const selectedAddress = selectedConversation ? directAddress(selectedConversation) : null
  const selectedGroup = selectedConversation?.kind === 'group'
    ? groups.find(group =>
        group.request.genesis.conversationId === selectedConversation.groupId)
    : undefined
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
      && !selectedGroupClosed
      && selectedGroupCanSend
      && !selectedGroupReadiness.blocksSending,
  )
  const canSendMedia = canSend && Boolean(
    selectedConversation?.kind === 'group'
      || noteSelected
      || selectedContact?.state === 'accepted',
  )

  const messages = useMemo(
    () =>
      selectedKey
        ? visibleHistory.filter((message) => conversationKey(message.conversation) === selectedKey)
        : [],
    [selectedKey, visibleHistory],
  )
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
    const latest = new Map<string, { message: ChatHistoryEntry; reaction: ChatReactionV1; reactor: string }>()
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
      const key = `${reaction.targetMessageId}\u0000${reactor}\u0000${reaction.emoji}`
      const previous = latest.get(key)
      if (!previous || compareContentOperations(previous.message, message) < 0) {
        latest.set(key, { message, reaction, reactor })
      }
    }
    const reactorsByTargetEmoji = new Map<string, Set<string>>()
    for (const { reaction, reactor } of latest.values()) {
      if (!reaction.active) continue
      const key = `${reaction.targetMessageId}\u0000${reaction.emoji}`
      const reactors = reactorsByTargetEmoji.get(key) ?? new Set<string>()
      reactors.add(reactor)
      reactorsByTargetEmoji.set(key, reactors)
    }
    const result = new Map<string, ReactionAggregate[]>()
    for (const targetMessageId of targetIds) {
      const aggregates = CHAT_REACTION_EMOJIS.flatMap(emoji => {
        const reactors = reactorsByTargetEmoji.get(`${targetMessageId}\u0000${emoji}`)
        return reactors?.size
          ? [{ emoji, count: reactors.size, reactedBySelf: reactors.has(selfAddress) }]
          : []
      })
      if (aggregates.length > 0) result.set(targetMessageId, aggregates)
    }
    return result
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
      void Promise.all([service.devices(), service.historyTransfers()])
        .then(([nextDevices, nextTransfers]) => {
          if (!cancelled) {
            setDevices(nextDevices)
            setHistoryTransfers(nextTransfers.transfers)
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

  async function refreshHistoryTransfers() {
    if (!service) return
    setHistoryTransfers((await service.historyTransfers()).transfers)
  }

  async function requestChatHistory() {
    if (!service) return
    setHistoryTransferBusy('request')
    try {
      await service.requestHistoryTransfer()
      await refreshHistoryTransfers()
      toast.success(t('chat.devices.historyRequested'))
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setHistoryTransferBusy(null)
    }
  }

  async function approveChatHistory(transfer: ChatHistoryTransferSummary) {
    if (!service) return
    setHistoryTransferBusy(transfer.transferId)
    try {
      await service.approveHistoryTransfer(transfer.request)
      await refreshHistoryTransfers()
      toast.success(t('chat.devices.historyApproved'))
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setHistoryTransferBusy(null)
    }
  }

  async function restoreChatHistory(transfer: ChatHistoryTransferSummary) {
    if (!service) return
    setHistoryTransferBusy(transfer.transferId)
    try {
      let result = await service.downloadHistoryTransfer(transfer.transferId)
      for (let attempt = 0; !result.ready && attempt < 20; attempt += 1) {
        await new Promise(resolve => window.setTimeout(resolve, 500))
        result = await service.downloadHistoryTransfer(transfer.transferId)
      }
      if (result.ready) {
        setDevicesOpen(false)
        toast.success(t('chat.devices.historyRestored', { count: result.importedCount ?? 0 }))
        window.setTimeout(() => window.location.reload(), 0)
      } else {
        await refreshHistoryTransfers()
        toast.info(t('chat.devices.historyUploading'))
      }
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setHistoryTransferBusy(null)
    }
  }

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' })
  }, [messages.length, selectedKey])

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

  async function sendAttachmentFile(file: File) {
    if (!service || !selectedConversation || !auth.accessToken || sending ||
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
      })
      const summary = await service.sendAttachment(
        selectedConversation,
        uploaded.descriptor,
        uploaded.storageReferenceId,
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
    }
  }

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
                <p className="text-xs text-muted-foreground">
                  {t('chat.devices.historyWarning')}
                </p>
                <div className="grid gap-3 border-t pt-4" data-testid="chat-history-recovery">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <h3 className="text-sm font-medium">{t('chat.devices.historyTitle')}</h3>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {t('chat.devices.historyDescription')}
                      </p>
                    </div>
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      disabled={historyTransferBusy !== null || historyTransfers.some(transfer =>
                        transfer.requestingDeviceId === service?.deviceId)}
                      onClick={() => void requestChatHistory()}
                      data-testid="chat-history-request"
                    >
                      {historyTransferBusy === 'request'
                        ? <Loader2 className="h-4 w-4 animate-spin" />
                        : <Download className="mr-2 h-4 w-4" />}
                      {t('chat.devices.historyRequest')}
                    </Button>
                  </div>
                  {historyTransfers.map(transfer => {
                    const requestingHere = transfer.requestingDeviceId === service?.deviceId
                    const busy = historyTransferBusy === transfer.transferId
                    return (
                      <div
                        key={transfer.transferId}
                        className="flex items-center justify-between gap-3 rounded-lg border p-3"
                        data-testid={`chat-history-transfer-${transfer.transferId}`}
                      >
                        <div className="min-w-0">
                          <p className="text-sm font-medium">
                            {requestingHere
                              ? t('chat.devices.historyThisDevice')
                              : t('chat.devices.historyOtherDevice', {
                                  device: transfer.requestingDeviceId,
                                })}
                          </p>
                          <p className="mt-1 text-xs text-muted-foreground">
                            {transfer.state === 'accepted'
                              ? t('chat.devices.historyReady', { count: transfer.frameCount })
                              : t('chat.devices.historyPending')}
                          </p>
                        </div>
                        {requestingHere && transfer.acceptance ? (
                          <Button
                            type="button"
                            size="sm"
                            disabled={historyTransferBusy !== null}
                            onClick={() => void restoreChatHistory(transfer)}
                          >
                            {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                            {t('chat.devices.historyRestore')}
                          </Button>
                        ) : !requestingHere && transfer.state === 'pending' ? (
                          <Button
                            type="button"
                            size="sm"
                            disabled={historyTransferBusy !== null}
                            onClick={() => void approveChatHistory(transfer)}
                          >
                            {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                            {t('chat.devices.historyApprove')}
                          </Button>
                        ) : null}
                      </div>
                    )
                  })}
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
                    aria-label="Chat storage"
                    data-testid="chat-storage-button"
                  >
                    <HardDrive className="h-5 w-5" />
                  </Button>
                </DialogTrigger>
                <DialogContent className="max-w-lg">
                  <DialogHeader>
                    <DialogTitle>Account storage</DialogTitle>
                    <DialogDescription>
                      Drive and Chat share one quota. Conversation labels are decrypted and calculated only on this device.
                    </DialogDescription>
                  </DialogHeader>
                  {mediaStorageLoading || !mediaStorage ? (
                    <div className="flex items-center justify-center gap-2 py-10 text-sm text-muted-foreground">
                      <Loader2 className="h-4 w-4 animate-spin" /> Loading encrypted accounting…
                    </div>
                  ) : (
                    <div className="grid gap-4" data-testid="chat-storage-summary">
                      <div className="rounded-lg border p-4">
                        <div className="flex justify-between text-sm font-medium">
                          <span>{formatBytes(mediaStorage.totalUsedBytes)} used</span>
                          <span>{formatBytes(mediaStorage.totalQuotaBytes)}</span>
                        </div>
                        <div className="mt-3 h-2 overflow-hidden rounded-full bg-muted">
                          <div
                            className="h-full bg-primary"
                            style={{ width: `${Math.min(100, mediaStorage.totalQuotaBytes > 0
                              ? mediaStorage.totalUsedBytes * 100 / mediaStorage.totalQuotaBytes
                              : 0)}%` }}
                          />
                        </div>
                        <div className="mt-3 grid grid-cols-2 gap-3 text-sm">
                          <div className="rounded bg-muted/50 p-2">
                            <span className="block text-xs text-muted-foreground">Drive</span>
                            {formatBytes(mediaStorage.driveBytes)}
                          </div>
                          <div className="rounded bg-muted/50 p-2">
                            <span className="block text-xs text-muted-foreground">Chat media</span>
                            {formatBytes(mediaStorage.chatMediaBytes)}
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

          {groups.length > 0 && (
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
            {(noteSelected || selectedGroup) && (
              <ShieldCheck
                className="h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400"
                aria-label="End-to-end encrypted"
              />
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
                />
              ))}
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
                  <Button
                    type="button"
                    size="icon"
                    variant="ghost"
                    disabled={!service || !canSendMedia || sending}
                    onClick={() => attachmentInputRef.current?.click()}
                    aria-label="Send encrypted attachment"
                    data-testid="chat-attachment-button"
                  >
                    <Paperclip className="h-4 w-4" />
                  </Button>
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
                      : selectedConversation
                    ? t('chat.messagePeer', {
                        peer: selectedTitle,
                      })
                    : t('chat.selectConversation')
                }
                disabled={!service || !canSend || sending || mutationSending}
                maxLength={16_000}
                autoComplete="off"
              />
              <Button type="submit" size="icon" disabled={!draft.trim() || !service || !canSend || sending || mutationSending}>
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
  repliedMessage,
  repliedMessageMutation,
  mutation,
  onReply,
  reactions = [],
  reactionBusy,
  onReact,
  onEdit,
  onDelete,
  mutationBusy,
  receipt,
}: {
  message: ChatHistoryEntry
  newerClientLabel: string
  accessToken?: string
  repliedMessage?: ChatHistoryEntry
  repliedMessageMutation?: MessageMutationState
  mutation?: MessageMutationState
  onReply?: () => void
  reactions?: ReactionAggregate[]
  reactionBusy?: string | null
  onReact?: (emoji: ChatReactionEmoji, active: boolean) => void
  onEdit?: () => void
  onDelete?: () => void
  mutationBusy?: boolean
  receipt?: MessageReceiptState
}) {
  const { t } = useTranslation()
  const outgoing = message.direction === 'outgoing'
  const [downloading, setDownloading] = useState(false)
  const attachment = message.content.attachment
  return (
    <div
      className={cn('group flex items-center gap-1', outgoing ? 'justify-end' : 'justify-start')}
      data-testid="chat-message"
    >
      {outgoing && (
        <MessageActions
          onReply={onReply}
          onReact={onReact}
          reactionBusy={reactionBusy}
          onEdit={onEdit}
          onDelete={onDelete}
          mutationBusy={mutationBusy}
        />
      )}
      <div
        className={cn(
          'max-w-[82%] rounded-2xl px-3.5 py-2 shadow-sm md:max-w-[70%]',
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
          <div className="flex min-w-52 items-center gap-3">
            <FileText className="h-7 w-7 shrink-0" />
            <span className="min-w-0 flex-1">
              <span className="block truncate text-sm font-medium">{attachment.filename}</span>
              <span className={cn(
                'block text-[11px]',
                outgoing ? 'text-primary-foreground/70' : 'text-muted-foreground',
              )}>
                {formatBytes(attachment.plaintextBytes)} · encrypted
              </span>
            </span>
            <Button
              type="button"
              size="icon"
              variant={outgoing ? 'secondary' : 'ghost'}
              className="h-8 w-8 shrink-0"
              disabled={!accessToken || downloading}
              onClick={() => {
                if (!accessToken || downloading) return
                setDownloading(true)
                void downloadChatMediaV1(attachment, accessToken)
                  .catch(() => toast.error('Encrypted attachment download failed'))
                  .finally(() => setDownloading(false))
              }}
              aria-label={`Download ${attachment.filename}`}
            >
              {downloading
                ? <Loader2 className="h-4 w-4 animate-spin" />
                : <Download className="h-4 w-4" />}
            </Button>
          </div>
        ) : (
          <p className="whitespace-pre-wrap break-words text-sm">
            {mutation?.editedText ?? message.content.text ?? newerClientLabel}
          </p>
        )}
        {!mutation?.deleted && reactions.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1" data-testid="chat-reactions">
            {reactions.map(reaction => (
              <button
                key={reaction.emoji}
                type="button"
                className={cn(
                  'rounded-full border px-2 py-0.5 text-xs transition-colors',
                  reaction.reactedBySelf
                    ? outgoing
                      ? 'border-primary-foreground/70 bg-primary-foreground/20'
                      : 'border-primary bg-primary/10'
                    : outgoing
                      ? 'border-primary-foreground/30 bg-primary-foreground/10'
                      : 'bg-muted/60',
                )}
                disabled={!onReact || reactionBusy !== null && reactionBusy !== undefined}
                onClick={() => onReact?.(reaction.emoji, !reaction.reactedBySelf)}
                aria-label={reaction.reactedBySelf
                  ? t('chat.reactions.remove', { emoji: reaction.emoji })
                  : t('chat.reactions.addEmoji', { emoji: reaction.emoji })}
                data-testid="chat-reaction-aggregate"
                data-emoji={reaction.emoji}
              >
                {reaction.emoji} {reaction.count}
              </button>
            ))}
          </div>
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
      {!outgoing && (
        <MessageActions
          onReply={onReply}
          onReact={onReact}
          reactionBusy={reactionBusy}
        />
      )}
    </div>
  )
}

function MessageActions({
  onReply,
  onReact,
  reactionBusy,
  onEdit,
  onDelete,
  mutationBusy,
}: {
  onReply?: () => void
  onReact?: (emoji: ChatReactionEmoji, active: boolean) => void
  reactionBusy?: string | null
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
          <DropdownMenuContent className="min-w-0" data-testid="chat-reaction-picker">
            <div className="flex p-1">
              {CHAT_REACTION_EMOJIS.map(emoji => (
                <DropdownMenuItem
                  key={emoji}
                  className="cursor-pointer px-2 text-lg"
                  onSelect={() => onReact(emoji, true)}
                  aria-label={t('chat.reactions.addEmoji', { emoji })}
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

function compareContentOperations(left: ChatHistoryEntry, right: ChatHistoryEntry): number {
  if (left.timestampMs !== right.timestampMs) return left.timestampMs - right.timestampMs
  const sequence = compareDecimalStrings(left.content.seq, right.content.seq)
  if (sequence !== 0) return sequence
  const device = (left.senderDeviceId ?? 0) - (right.senderDeviceId ?? 0)
  return device !== 0 ? device : left.id.localeCompare(right.id)
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
