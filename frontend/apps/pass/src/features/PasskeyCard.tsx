import { Copy, KeyRound } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@kutup/ui/components/button'
import { copyText } from '@kutup/ui/lib/clipboard'
import type { PasskeyView } from '../vault/types'

/**
 * An entry's passkey (KeePassXC's KPEX_PASSKEY_* fields): the site, the user
 * and the credential. The private key is never here: the vault's view leaves
 * it out (kutup_pass::passkey), so the page never holds it.
 */
export function PasskeyCard({ passkey }: { passkey: PasskeyView }) {
  const { t } = useTranslation()
  const rows: { label: string; value: string; mono?: boolean }[] = [
    { label: t('passkey.site'), value: passkey.relyingParty },
    { label: t('passkey.username'), value: passkey.username },
    { label: t('passkey.credentialId'), value: passkey.credentialId, mono: true },
  ].filter((row) => row.value !== '')
  return (
    <section className="mt-6 rounded-md border border-border p-3" aria-label={t('passkey.title')} data-testid="passkey-card">
      <h3 className="flex items-center gap-2 text-sm font-medium">
        <KeyRound className="size-4 text-muted-foreground" aria-hidden />
        {t('passkey.title')}
      </h3>
      <dl className="mt-2 grid grid-cols-[auto_1fr] items-center gap-x-4 gap-y-1 text-sm">
        {rows.map((row) => (
          <div key={row.label} className="contents">
            <dt className="text-muted-foreground">{row.label}</dt>
            <dd className="flex min-w-0 items-center gap-1">
              <span className={row.mono ? 'truncate font-mono text-xs' : 'truncate'}>{row.value}</span>
              <Button variant="ghost" size="icon" aria-label={t('passkey.copy', { what: row.label })} onClick={() => void copyText(row.value).then(() => toast.success(t('passkey.copied', { what: row.label })))}>
                <Copy />
              </Button>
            </dd>
          </div>
        ))}
      </dl>
      <p className="mt-2 text-xs text-muted-foreground">{passkey.hasPrivateKey ? t('passkey.keptHint') : t('passkey.noKeyHint')}</p>
    </section>
  )
}
