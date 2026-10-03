import { useEffect, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { openJoinLink } from '../../lib/joinLink'

/** `/join#…`: a group link opened in this app shows what it leads to over the chats. */
export function JoinLinkRoute() {
  // Read before <Navigate> (whose effect runs first) replaces the URL.
  const [href] = useState(() => window.location.href)
  useEffect(() => {
    openJoinLink(href)
  }, [href])
  return <Navigate to="/" replace />
}
