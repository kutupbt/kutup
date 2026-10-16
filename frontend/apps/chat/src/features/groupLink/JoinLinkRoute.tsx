import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Navigate } from 'react-router-dom'
import { toast } from 'sonner'
import { useChat } from '../../app/chatStore'
import { openJoinLink } from '../../lib/joinLink'

/**
 * `/join#…`: a group link opened in this app shows what it leads to over the
 * chats. A server without groups says so instead.
 */
export function JoinLinkRoute() {
  const { t } = useTranslation()
  const { capabilities, status } = useChat()
  // Read before <Navigate> (whose effect runs first) replaces the URL.
  const [href] = useState(() => window.location.href)
  const known = capabilities !== null || status === 'failed'
  const groups = capabilities?.mlsGroups === true
  useEffect(() => {
    if (!known) return
    if (groups) openJoinLink(href)
    else toast.message(t('chat.groupLink.groupsOff'))
  }, [known, groups, href, t])
  return known ? <Navigate to="/" replace /> : null
}
