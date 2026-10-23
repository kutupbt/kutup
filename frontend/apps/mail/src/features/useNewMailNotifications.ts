import { useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { fetchNewMail, type NewMail } from '@kutup/mail-core/api'
import { notificationStatus, showNotification } from '@kutup/ui/lib/desktopNotifications'

// New-mail notifications while Mail is open (docs/plans/mail-parity.md, P6),
// as Proton's `useNewEmailNotification`: one for each new unread message in
// the Inbox, Starred or a folder with notifications on, opening it when
// clicked; more than three at once as one.

const POLL_MS = 30_000
const MAX_EACH = 3
const REMEMBERED = 500

/** Where a notified message opens: its folder, or Starred. */
export function placeOf(mail: NewMail): string {
  if (mail.folder === 'inbox') return `/inbox/${mail.threadId}`
  if (mail.folder === 'custom' && mail.customFolder) return `/f/${mail.customFolder}/${mail.threadId}`
  return `/starred/${mail.threadId}`
}

export function useNewMailNotifications(): void {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const latest = useRef({ t, navigate })
  latest.current = { t, navigate }

  useEffect(() => {
    let live = true
    let after: string | null = null
    const shown = new Set<string>()
    const tell = (fresh: NewMail[], more: boolean) => {
      const { t, navigate } = latest.current
      if (fresh.length > MAX_EACH || more) {
        showNotification(t('notifications.title'), { body: t('notifications.grouped', { count: fresh.length + (more ? 1 : 0) }), tag: 'kutup-mail-grouped' }, () => void navigate('/inbox'))
        return
      }
      for (const mail of fresh) {
        const sender = mail.fromName || mail.fromAddress
        showNotification(t('notifications.title'), { body: t('notifications.body', { sender, subject: mail.subject || t('list.noSubject') }), tag: mail.id }, () => void navigate(placeOf(mail)))
      }
    }
    const tick = async () => {
      try {
        const page = await fetchNewMail(after)
        if (!live) return
        const fresh = page.messages.filter((mail) => !shown.has(mail.id))
        fresh.forEach((mail) => shown.add(mail.id))
        // The first answer only sets where to start.
        if (after !== null && fresh.length && notificationStatus() === 'granted') tell(fresh, page.more)
        after = page.now
        if (shown.size > REMEMBERED) [...shown].slice(0, shown.size - REMEMBERED).forEach((id) => shown.delete(id))
      } catch {
        // The next poll tries again.
      }
    }
    void tick()
    const timer = window.setInterval(() => void tick(), POLL_MS)
    return () => {
      live = false
      window.clearInterval(timer)
    }
  }, [])
}
