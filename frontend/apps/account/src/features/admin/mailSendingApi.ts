import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import api from '@kutup/session/client'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { adminKey } from './api'

// Sending safety for administrators (docs/plans/mail.md): the shapes and
// the update shared by Administration → Mail sending and the user page.

export interface MailSender {
  userId: string
  email: string
  username: string
  sentDay: number
  sentWeek: number
  bouncesWeek: number
  spamRefusedWeek: number
  perHour: number | null
  perDay: number | null
  pausedAt: string | null
  pausedReason: 'admin' | 'bounces' | 'spam' | null
  flaggedAt: string | null
  flagReason: 'bounces' | 'spam' | null
}

export interface Change {
  perHour?: number | null
  perDay?: number | null
  paused?: boolean
  clearFlag?: boolean
}

export const sendersKey = [...adminKey, 'mail-senders'] as const

/** Saves an account's limits, pause or flag, then refreshes the admin views. */
export function useUpdateMailSending(onDone?: () => void) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ userId, change }: { userId: string; change: Change }) => {
      await api.put(`/admin/users/${userId}/mail-sending`, change)
    },
    onSuccess: async () => {
      onDone?.()
      toast.success(t('admin.mailSending.saved'))
      await queryClient.invalidateQueries({ queryKey: adminKey })
    },
    onError: (error) => toast.error(apiErrorMessage(error, t('common.tryAgain'))),
  })
}
