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
  Loader2,
  MessageCircle,
  MessageSquareWarning,
  Plus,
  QrCode,
  RefreshCw,
  Send,
  Shield,
  ShieldCheck,
  Trash2,
  UserMinus,
  Users,
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
import { QRCodeSVG } from 'qrcode.react'
import { useIsMobile } from '@/hooks/useIsMobile'
import { useAppSelector } from '@/store'
import api from '@/api/client'
import { ChatService, ChatServiceError } from '@/chat/service'
import { MlsSendError } from '@/chat/mls-service'
import { MlsGroupSecurityDetails } from '@/chat/MlsGroupSecurityDetails'
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
  ChatHistoryEntry,
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
  TransparencyMonitorStatus,
} from '@/chat/types'
import { cn } from '@/lib/utils'
import { copyText } from '@/lib/format'

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
  const [transparencyStatuses, setTransparencyStatuses] =
    useState<Record<string, TransparencyMonitorStatus>>({})
  const [selectedConversation, setSelectedConversation] = useState<ConversationId | null>(null)
  const [newPeer, setNewPeer] = useState('')
  const [draft, setDraft] = useState('')
  const [loading, setLoading] = useState(true)
  const [sending, setSending] = useState(false)
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
  const [error, setError] = useState<string | null>(null)
  const endRef = useRef<HTMLDivElement>(null)
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
      try {
        const [nextHistory, nextAttention, nextContacts, nextProfile, nextProfiles, nextTransparency, nextGroups, nextInvitations, nextInvitationFeedback, nextOwnerApprovals] = await Promise.all([
          opened.history(),
          opened.inboundAttention(),
          opened.contacts(),
          opened.profile(),
          opened.profiles(),
          opened.transparencyStatus(),
          capabilities.mlsGroups ? opened.groups() : Promise.resolve([]),
          capabilities.mlsGroups ? opened.groupInvitations() : Promise.resolve([]),
          capabilities.mlsGroups ? opened.groupInvitationFeedback() : Promise.resolve([]),
          capabilities.mlsGroups ? opened.pendingGroupOwnerApprovals() : Promise.resolve([]),
        ])
        if (!cancelled) {
          setHistory(nextHistory)
          setAttention(nextAttention)
          setContacts(nextContacts)
          setLocalProfile(nextProfile)
          setPeerProfiles(nextProfiles)
          setGroups(nextGroups)
          setGroupInvitations(nextInvitations)
          setGroupInvitationFeedback(nextInvitationFeedback)
          setOwnerApprovalRequests(nextOwnerApprovals)
          if (nextTransparency) {
            setTransparencyStatuses((current) => ({ ...current, local: nextTransparency }))
          }
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
        if (!cancelled) setError(errorMessage(cause, t))
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

  const peers = useMemo(() => {
    const latest = new Map<string, { conversation: ConversationId; message: ChatHistoryEntry }>()
    for (const message of history) {
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
  }, [contactsByPeer, history, selfAddress])

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
                message: history
                  .filter((message) => directAddress(message.conversation) === contact.peer)
                  .at(-1),
              }]
            : []
        })
        .sort((left, right) => right.contact.updatedAtMs - left.contact.updatedAtMs),
    [contacts, history],
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
  const selectedAccount = selectedAddress ? parseAccountAddress(selectedAddress) : null
  const selectedTransparencyScope = selectedAccount?.server &&
    selectedAccount.server !== capabilities.serverName
    ? selectedAccount.server
    : 'local'
  const transparencyStatus = transparencyStatuses[selectedTransparencyScope]
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

  useEffect(() => {
    if (!service || selectedTransparencyScope === 'local') return
    let cancelled = false
    void service.monitorTransparency(selectedTransparencyScope)
      .then((status) => {
        if (!cancelled) {
          setTransparencyStatuses((current) => ({
            ...current,
            [selectedTransparencyScope]: status,
          }))
        }
      })
      .catch(() => undefined)
    return () => {
      cancelled = true
    }
  }, [selectedTransparencyScope, service])

  async function retryTransparency() {
    if (!service) return
    try {
      const status = await service.monitorTransparency(selectedTransparencyScope)
      setTransparencyStatuses((current) => ({
        ...current,
        [selectedTransparencyScope]: status,
      }))
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    }
  }

  const messages = useMemo(
    () =>
      selectedKey
        ? history.filter((message) => conversationKey(message.conversation) === selectedKey)
        : [],
    [history, selectedKey],
  )

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
    if (!service || !selectedConversation || !text || sending) return
    setSending(true)
    setDraft('')
    try {
      const summary = await service.send(selectedConversation, text)
      if (summary.safetyNumberChanges.length > 0) {
        toast.warning(t('chat.safetyNumberChanged'))
      }
      setHistory(await service.history())
    } catch (cause) {
      setDraft(text)
      toast.error(errorMessage(cause, t))
    } finally {
      setSending(false)
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
        <aside className="flex w-full shrink-0 flex-col border-r bg-sidebar md:w-80">
          <header className="flex h-16 items-center gap-3 border-b px-4">
            <Button variant="ghost" size="icon" onClick={() => navigate('/drive')}>
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
              <h1 className="font-semibold">{t('chat.title')}</h1>
              <p className="truncate text-xs text-muted-foreground">
                {t('chat.encryptedDevice', { device: service?.deviceId ?? '…' })}
              </p>
            </div>
            {transparencyStatus?.state === 'verificationFailed' ? (
              <AlertTriangle
                className="h-5 w-5 text-destructive"
                aria-label={t('chat.transparency.verificationFailed')}
              />
            ) : (
              <ShieldCheck
                className={cn(
                  'h-5 w-5',
                  transparencyStatus?.state === 'unavailable'
                    ? 'text-warning'
                    : 'text-success',
                )}
                aria-label={
                  transparencyStatus?.state === 'unavailable'
                    ? t('chat.transparency.unavailable')
                    : t('chat.transparency.healthy')
                }
              />
            )}
            {selfAccount?.server && selfAddress && (
              <Dialog>
                <DialogTrigger asChild>
                  <Button variant="ghost" size="icon" aria-label={t('chat.contact.open')}>
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
                      {message?.content.text ?? t('chat.newerClient')}
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
                const latest = history.filter(message =>
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
                        {latest?.content.text ?? `${group.currentRoster.length} members · epoch ${group.lastFinalizedEpoch}`}
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
                    {message.content.text ?? t('chat.newerClient')}
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
              <p className="flex items-center gap-1 text-xs text-muted-foreground">
                <ShieldCheck className="h-3 w-3" />
                <span className="truncate">
                  {!noteSelected && selectedProfile?.displayName
                    ? selectedLabel
                    : t('chat.protocolEncryption')}
                </span>
              </p>
            </div>
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
                      Suite 0x0002, anonymous delivery, 1024-byte padding, and two retained past
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
                        A fresh KeyPackage is verified through key transparency before the membership commit is ordered.
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
            <TransparencyDetails
              scope={selectedTransparencyScope}
              capabilities={capabilities}
              status={transparencyStatus}
            />
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
          {transparencyStatus?.state === 'verificationFailed' && (
            <div className="flex items-center gap-2 border-b border-destructive/30 bg-destructive-faint px-4 py-2 text-sm text-destructive">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span className="flex-1">{t('chat.transparency.verificationFailed')}</span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => void retryTransparency()}
                disabled={!service}
              >
                {t('chat.transparency.retry')}
              </Button>
            </div>
          )}
          {transparencyStatus?.state === 'unavailable' && (
            <div className="flex items-center gap-2 border-b border-warning/30 bg-warning-faint px-4 py-2 text-sm">
              <AlertTriangle className="h-4 w-4 shrink-0 text-warning" />
              <span className="flex-1">{t('chat.transparency.unavailable')}</span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => void retryTransparency()}
                disabled={!service}
              >
                {t('chat.transparency.retry')}
              </Button>
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
            <div className="mx-auto flex max-w-3xl items-end gap-2">
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
                disabled={!service || !canSend || sending}
                maxLength={16_000}
                autoComplete="off"
              />
              <Button type="submit" size="icon" disabled={!draft.trim() || !service || !canSend || sending}>
                {sending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                <span className="sr-only">{t('chat.send')}</span>
              </Button>
            </div>
          </form>
        </main>
      )}
    </div>
  )
}

interface TransparencyPolicyEnvelope {
  sequence: string | number
  payloadDigest: string
  issuedAt: number
  payload: string
}

interface TransparencyPolicyHistory {
  domain: string
  policies: TransparencyPolicyEnvelope[]
}

interface TransparencyPolicyPayload {
  logId: string
  operatorKeyId: string
  operatorPublicKey: string
  requiredQuorum: number
  witnesses: Array<{
    witnessId: string
    keyId: string
    publicKey: string
    publicEndpoint: string
  }>
  maximumCheckpointAgeSeconds: number
}

interface TransparencyCheckpointDetails {
  checkpoint: { logId: string; treeSize: string | number; rootHash: string }
  mapRoot: string
  authentication: {
    issuedAt: number
    operatorKeyId: string
    operatorPublicKey: string
    witnesses: Array<{ witnessId: string; keyId: string }>
  }
}

interface TransparencyServerStatus {
  policySequence: string | number
  lastSuccessfulAt?: string
  nextAttemptAt: string
  failureClass?: string
  warning: boolean
  blocked: boolean
  evidenceDigest?: string
}

function TransparencyDetails({
  scope,
  capabilities,
  status,
}: {
  scope: string
  capabilities: ChatCapabilities
  status?: TransparencyMonitorStatus
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [failure, setFailure] = useState(false)
  const [history, setHistory] = useState<TransparencyPolicyHistory | null>(null)
  const [policy, setPolicy] = useState<TransparencyPolicyPayload | null>(null)
  const [checkpoint, setCheckpoint] = useState<TransparencyCheckpointDetails | null>(null)
  const [serverStatus, setServerStatus] = useState<TransparencyServerStatus | null>(null)
  const domain = scope === 'local' ? capabilities.serverName : scope

  useEffect(() => {
    if (!open || !domain) return
    let cancelled = false
    setLoading(true)
    setFailure(false)
    const policyRequest = api
      .get<TransparencyPolicyHistory>(
        `/chat/transparency/domains/${encodeURIComponent(domain)}/policy`,
      )
      .then((response) => response.data)
    const checkpointRequest = api
      .get<TransparencyCheckpointDetails>(
        scope === 'local'
          ? '/chat/transparency/checkpoint'
          : `/chat/transparency/domains/${encodeURIComponent(domain)}/checkpoint`,
        { params: { fromTreeSize: '0' } },
      )
      .then((response) => response.data)
    const statusRequest = scope === 'local'
      ? Promise.resolve(null)
      : api
          .get<TransparencyServerStatus>(
            `/chat/transparency/domains/${encodeURIComponent(domain)}/status`,
          )
          .then((response) => response.data)
    void Promise.all([policyRequest, checkpointRequest, statusRequest])
      .then(([nextHistory, nextCheckpoint, nextServerStatus]) => {
        const current = nextHistory.policies.at(-1)
        if (!current) throw new Error('empty transparency policy history')
        const nextPolicy = decodePolicyPayload(current.payload)
        if (!cancelled) {
          setHistory(nextHistory)
          setPolicy(nextPolicy)
          setCheckpoint(nextCheckpoint)
          setServerStatus(nextServerStatus)
        }
      })
      .catch(() => {
        if (!cancelled) setFailure(true)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [domain, open, scope])

  const failed = status?.state === 'verificationFailed' || serverStatus?.blocked
  const warning = status?.state === 'unavailable' || serverStatus?.warning
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          disabled={!domain}
          aria-label={t('chat.transparency.details', { defaultValue: 'Transparency details' })}
        >
          {failed
            ? <AlertTriangle className="h-4 w-4 text-destructive" />
            : <ShieldCheck className={cn('h-4 w-4', warning ? 'text-warning' : 'text-success')} />}
        </Button>
      </DialogTrigger>
      <DialogContent className="max-h-[85vh] max-w-2xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {t('chat.transparency.details', { defaultValue: 'Transparency details' })}
          </DialogTitle>
          <DialogDescription className="break-all">{domain}</DialogDescription>
        </DialogHeader>
        {loading && (
          <div className="flex items-center gap-2 py-8 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            {t('common.loading', { defaultValue: 'Loading…' })}
          </div>
        )}
        {failure && (
          <div className="rounded-lg border border-warning/30 bg-warning-faint p-3 text-sm">
            {t('chat.transparency.detailsUnavailable', {
              defaultValue: 'Detailed transparency evidence is temporarily unavailable.',
            })}
          </div>
        )}
        {!loading && policy && checkpoint && history && (
          <div className="grid gap-4 text-sm">
            <div className="grid grid-cols-2 gap-3 rounded-lg border bg-muted/30 p-3">
              <Detail label="Client state" value={status?.state ?? 'unknown'} />
              <Detail label="Policy sequence" value={String(history.policies.at(-1)?.sequence)} />
              <Detail label="History length" value={String(history.policies.length)} />
              <Detail label="Required quorum" value={String(policy.requiredQuorum)} />
              <Detail label="Tree size" value={String(checkpoint.checkpoint.treeSize)} />
              <Detail
                label="Checkpoint age"
                value={formatAge(checkpoint.authentication.issuedAt)}
              />
              {serverStatus?.lastSuccessfulAt && (
                <Detail label="Server last verified" value={serverStatus.lastSuccessfulAt} />
              )}
              {serverStatus?.nextAttemptAt && (
                <Detail label="Server next attempt" value={serverStatus.nextAttemptAt} />
              )}
              {serverStatus?.failureClass && (
                <Detail label="Failure class" value={serverStatus.failureClass} />
              )}
            </div>
            <Fingerprint label="Log ID" value={policy.logId} />
            <Fingerprint label="Checkpoint root" value={checkpoint.checkpoint.rootHash} />
            <Fingerprint label="Sparse-map root" value={checkpoint.mapRoot} />
            <Fingerprint label="Operator key ID" value={policy.operatorKeyId} />
            <Fingerprint label="Operator public key" value={policy.operatorPublicKey} />
            {serverStatus?.evidenceDigest && (
              <Fingerprint label="Blocking evidence digest" value={serverStatus.evidenceDigest} />
            )}
            <div>
              <h3 className="mb-2 font-medium">Witnesses</h3>
              <div className="grid gap-2">
                {policy.witnesses.map((witness) => (
                  <div key={witness.witnessId} className="rounded-lg border p-3">
                    <div className="font-medium">{witness.witnessId}</div>
                    <code className="mt-1 block break-all text-xs text-muted-foreground">
                      {witness.keyId}
                    </code>
                    <code className="mt-1 block break-all text-xs text-muted-foreground">
                      {witness.publicKey}
                    </code>
                    <div className="mt-1 break-all text-xs text-muted-foreground">
                      {witness.publicEndpoint}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <details className="rounded-lg border p-3">
              <summary className="cursor-pointer font-medium">Authenticated policy history</summary>
              <div className="mt-3 grid gap-2">
                {history.policies.map((entry) => (
                  <div key={String(entry.sequence)} className="rounded bg-muted/40 p-2 text-xs">
                    <div>Sequence {String(entry.sequence)} · {formatTimestamp(entry.issuedAt)}</div>
                    <code className="mt-1 block break-all text-muted-foreground">
                      {entry.payloadDigest}
                    </code>
                  </div>
                ))}
              </div>
            </details>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="break-all font-medium">{value}</div>
    </div>
  )
}

function Fingerprint({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="mb-1 text-xs font-medium text-muted-foreground">{label}</div>
      <code className="block break-all rounded-lg border bg-muted/30 p-2 text-xs">{value}</code>
    </div>
  )
}

function decodePolicyPayload(payload: string): TransparencyPolicyPayload {
  const binary = atob(payload)
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0))
  return JSON.parse(new TextDecoder().decode(bytes)) as TransparencyPolicyPayload
}

function formatAge(unixSeconds: number): string {
  const seconds = Math.max(0, Math.round(Date.now() / 1000) - unixSeconds)
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  return `${Math.floor(seconds / 3600)}h`
}

function formatTimestamp(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toLocaleString()
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
          className="rounded-full"
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
}: {
  message: ChatHistoryEntry
  newerClientLabel: string
}) {
  const outgoing = message.direction === 'outgoing'
  return (
    <div className={cn('flex', outgoing ? 'justify-end' : 'justify-start')}>
      <div
        className={cn(
          'max-w-[82%] rounded-2xl px-3.5 py-2 shadow-sm md:max-w-[70%]',
          outgoing
            ? 'rounded-br-md bg-primary text-primary-foreground'
            : 'rounded-bl-md border bg-card',
        )}
      >
        <p className="whitespace-pre-wrap break-words text-sm">
          {message.content.text ?? newerClientLabel}
        </p>
        <span
          className={cn(
            'mt-1 flex items-center justify-end gap-1 text-[10px]',
            outgoing ? 'text-primary-foreground/70' : 'text-muted-foreground',
          )}
        >
          {formatTime(message.content.sentAt)}
          {outgoing && (message.delivered ? <CheckCheck className="h-3 w-3" /> : <Check className="h-3 w-3" />)}
        </span>
      </div>
    </div>
  )
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

function errorMessage(
  error: unknown,
  t: (key: string, options?: Record<string, unknown>) => string,
): string {
  if (error instanceof ChatServiceError) return t(`chat.errors.${error.code}`)
  if (error instanceof MlsSendError) return error.message
  if (error instanceof Error && error.message.startsWith('MLS ')) return error.message
  return t('chat.errors.unavailable')
}
