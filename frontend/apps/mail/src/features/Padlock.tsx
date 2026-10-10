import { Lock, LockKeyhole, ShieldAlert, ShieldCheck } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { MailMessage, OpenedMessage } from '@kutup/mail-core/api'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { cn } from '@kutup/ui/lib/cn'

type Kind =
  | 'verified'
  | 'endToEnd'
  | 'zeroAccess'
  | 'sentZeroAccess'
  | 'failed'
  | 'pgpEncrypted'
  | 'pgpEncryptedSigned'
  | 'pgpVerified'
  | 'pgpSigned'
  | 'pgpSignedVerified'

/** How a message was protected, as Proton's padlock tells it (`helpers/message/icon.ts`). */
function protectionOf(message: MailMessage, opened?: OpenedMessage): Kind {
  // OpenPGP mail from outside: a signature counts only with a pinned key.
  const pgp = opened?.pgp
  if (pgp) {
    if (opened.verified) return pgp.encrypted ? 'pgpVerified' : 'pgpSignedVerified'
    if (opened.signed && pgp.pinned) return 'failed'
    if (pgp.encrypted) return opened.signed ? 'pgpEncryptedSigned' : 'pgpEncrypted'
    if (opened.signed) return 'pgpSigned'
  }
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
  pgpEncrypted: LockKeyhole,
  pgpEncryptedSigned: LockKeyhole,
  pgpVerified: ShieldCheck,
  pgpSigned: Lock,
  pgpSignedVerified: ShieldCheck,
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
          kind === 'failed'
            ? 'text-destructive'
            : kind === 'zeroAccess' || kind === 'sentZeroAccess' || kind === 'pgpSigned'
              ? 'text-muted-foreground'
              : 'text-primary',
          className,
        )}
      >
        <Icon className="size-4" aria-hidden />
      </span>
    </Tooltip>
  )
}
