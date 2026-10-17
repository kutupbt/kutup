import { useEffect } from 'react'
import { appUrl } from '@kutup/session/apps'

/** Mail's old /groups address, sent on to Account settings (no page of its own). */
export function GroupsMoved() {
  useEffect(() => {
    window.location.replace(appUrl('account', '/settings/groups'))
  }, [])
  return null
}
