import { useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { getCursorColor, setCursorColor } from '@kutup/collab/identity'
import api from '@kutup/session/client'
import { broadcastColor } from '@kutup/session/sessionSync'
import { getSession, updateSession, useRequiredSession } from '@kutup/session/store'

/**
 * The colour collaborators see this person's cursor in, and a setter.
 *
 * It belongs to the account (saved on the server, synced to other tabs).
 * Until one is picked a random palette colour is kept in this browser so
 * the cursor is never invisible. A change applies at once and is rolled
 * back if the server refuses it.
 */
export function useCursorColor(): [string, (hex: string) => void] {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const color = session.color ?? getCursorColor()
  const change = useCallback(
    (hex: string) => {
      const previous = getSession()?.color ?? null
      updateSession({ color: hex })
      broadcastColor(hex)
      // Fallback for the next load, before the session is back.
      setCursorColor(hex)
      api.patch('/user/me', { color: hex }).catch(() => {
        updateSession({ color: previous })
        broadcastColor(previous)
        toast.error(t('editor.colorSaveFailed'))
      })
    },
    [t],
  )
  return [color, change]
}
