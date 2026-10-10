import { Lock, LockKeyhole, ShieldAlert, ShieldCheck } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { MailMessage, OpenedMessage } from '@kutup/mail-core/api'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { cn } from '@kutup/ui/lib/cn'

type Kind = 'verified' | 'endToEnd' | 'zeroAccess' | 'sentZeroAccess' | 'failed'

/** How a message was protected, as Proton's padlock tells it (`helpers/message/icon.ts`). */
function protectionOf(message: MailMessage, opened?: OpenedMessage): Kind {
  if (message.protection === 'end_to_end') {
    if (opened?.signed && !opened.verified) return 'failed'
    return opened?.verified ? 'verified' : 'endToEnd'
  }
  return message.direction === 'outbound' ? 'sentZeroAccess' : 'zeroAccess'
}

const ICON = {
  verified: ShieldCheck,
  endToEnd: LockKeyhole,
  zeroAccess: Lock,
  sentZeroAccess: Lock,
  failed: ShieldAlert,
} as const

export function Padlock({ message, opened, className }: { message: MailMessage; opened?: OpenedMessage; className?: string }) {
  const { t } = useTranslation()
  const kind = protectionOf(message, opened)
  const Icon = ICON[kind]
  const label = t(`padlock.${kind}`)
  return (
    <Tooltip label={label}>
      <span
        role="img"
        aria-label={label}
        className={cn(
          'inline-flex shrink-0',
          kind === 'failed' ? 'text-destructive' : kind === 'verified' || kind === 'endToEnd' ? 'text-primary' : 'text-muted-foreground',
          className,
        )}
      >
        <Icon className="size-4" aria-hidden />
      </span>
    </Tooltip>
  )
}
