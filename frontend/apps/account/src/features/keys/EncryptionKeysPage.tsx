import { Download, KeyRound, MoreHorizontal, Plus, ShieldAlert, ShieldCheck, Upload } from 'lucide-react'
import { useIsMutating, useMutationState } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { armorMailPublicKey, MAIL_KEY_FLAGS } from '@kutup/crypto'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { Card, CardContent } from '@kutup/ui/components/card'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@kutup/ui/components/dropdown-menu'
import { Mono } from '@kutup/ui/components/mono'
import { PageBody, PageHeader, Section } from '@kutup/ui/components/page'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { formatInstant } from '@kutup/ui/lib/format'
import { ExportKeyDialog, ImportKeyDialog, NewKeyDialog } from './KeyDialogs'
import { createMailKeyMutation, useChangeKey, useMailAddresses, type CheckedMailAddress, type KeyChange, type MailKey } from './mailKeys'

/**
 * Your email addresses and their encryption keys, as Proton's Settings →
 * Encryption and keys shows them (docs/plans/mail-address-keys.md). Each
 * address's key list is signed by this account, so anyone who has verified
 * you in Chat or Drive can trust these keys too.
 */
export function EncryptionKeysPage() {
  const { t } = useTranslation()
  const addresses = useMailAddresses()
  // Keys are created by the account shell on sign-in (useEnsureMailKeys).
  const creating = useIsMutating({ mutationKey: createMailKeyMutation }) > 0
  const failed = useMutationState({ filters: { mutationKey: createMailKeyMutation, status: 'error' } }).length > 0

  return (
    <PageBody width="prose">
      <PageHeader title={t('settings.keys.title')} description={t('settings.keys.description')} />
      {addresses.isPending ? (
        <Skeleton className="h-40 w-full" />
      ) : addresses.isError ? (
        <Alert variant="error">{apiErrorMessage(addresses.error, t('common.tryAgain'))}</Alert>
      ) : addresses.data.length === 0 ? (
        <Alert>{t('settings.keys.noAddress')}</Alert>
      ) : (
        addresses.data.map((address) => (
          <AddressKeys key={address.id} address={address} creating={creating} failed={failed} />
        ))
      )}
    </PageBody>
  )
}

function AddressKeys({ address, creating, failed }: { address: CheckedMailAddress; creating: boolean; failed: boolean }) {
  const { t } = useTranslation()
  const verified = address.verifiedList !== null
  const [dialog, setDialog] = useState<'new' | 'import' | null>(null)
  return (
    <Section title={address.address} description={t('settings.keys.addressHint')}>
      {address.keys.length === 0 ? (
        failed ? (
          <Alert variant="error">{t('settings.keys.createFailed')}</Alert>
        ) : (
          <Card>
            <CardContent className="flex items-center gap-3 p-5 text-sm text-muted-foreground">
              <KeyRound className="size-4" aria-hidden />
              {creating ? t('settings.keys.creating') : t('settings.keys.none')}
            </CardContent>
          </Card>
        )
      ) : (
        <>
          <p className="flex items-center gap-2 text-sm">
            {verified ? (
              <>
                <ShieldCheck className="size-4 text-status-ok" aria-hidden />
                {t('settings.keys.signedByAccount', { sequence: address.verifiedList!.sequence })}
              </>
            ) : (
              <>
                <ShieldAlert className="size-4 text-destructive" aria-hidden />
                <span className="text-destructive">{t('settings.keys.notSigned')}</span>
              </>
            )}
          </p>
          <Card>
            <CardContent className="divide-y divide-border p-0">
              {address.keys.map((key) => (
                <KeyRow key={key.id} address={address} mailKey={key} />
              ))}
            </CardContent>
          </Card>
          {verified ? (
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" size="sm" onClick={() => setDialog('new')}>
                <Plus />
                {t('settings.keys.new')}
              </Button>
              <Button variant="outline" size="sm" onClick={() => setDialog('import')}>
                <Upload />
                {t('settings.keys.import')}
              </Button>
            </div>
          ) : null}
          {dialog === 'new' ? <NewKeyDialog address={address} onClose={() => setDialog(null)} /> : null}
          {dialog === 'import' ? <ImportKeyDialog address={address} onClose={() => setDialog(null)} /> : null}
        </>
      )}
    </Section>
  )
}

/** `ABCD 1234 …`, the way fingerprints are read aloud. */
function fingerprintGroups(fingerprint: string): string[] {
  return fingerprint.toUpperCase().match(/.{1,4}/g) ?? [fingerprint]
}

function KeyRow({ address: owner, mailKey }: { address: CheckedMailAddress; mailKey: MailKey }) {
  const { t, i18n } = useTranslation()
  const address = owner.address
  const [busy, setBusy] = useState(false)
  const [dialog, setDialog] = useState<'export' | 'compromised' | null>(null)
  const change = useChangeKey()
  const signed = owner.verifiedList !== null
  const apply = (keyChange: KeyChange, done: string) =>
    change.mutate(
      { address: owner, fingerprint: mailKey.fingerprint, change: keyChange },
      {
        onSuccess: () => {
          toast.success(done)
          setDialog(null)
        },
        onError: (error) => {
          if (dialog === null) toast.error(apiErrorMessage(error, t('settings.keys.changeFailed')))
        },
      },
    )
  const canEncrypt = (mailKey.flags & MAIL_KEY_FLAGS.notObsolete) !== 0
  const canVerify = (mailKey.flags & MAIL_KEY_FLAGS.notCompromised) !== 0

  async function download() {
    setBusy(true)
    try {
      const armored = await armorMailPublicKey(mailKey.publicKey)
      const url = URL.createObjectURL(new Blob([armored], { type: 'application/pgp-keys' }))
      const link = document.createElement('a')
      link.href = url
      // Proton's name for the same file.
      link.download = `publickey.${address}-${mailKey.fingerprint}.asc`
      link.click()
      URL.revokeObjectURL(url)
    } catch (error) {
      toast.error(apiErrorMessage(error, t('settings.keys.downloadFailed')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-3 p-5" data-fingerprint={mailKey.fingerprint}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium">{t('settings.keys.algorithm')}</span>
        {mailKey.primary ? <Badge>{t('settings.keys.primary')}</Badge> : null}
        {canEncrypt ? null : <Badge variant="neutral">{t('settings.keys.obsolete')}</Badge>}
        {canVerify ? null : <Badge variant="neutral">{t('settings.keys.compromised')}</Badge>}
      </div>
      <div className="space-y-1">
        <p className="text-xs text-muted-foreground">{t('settings.keys.fingerprint')}</p>
        <Mono className="flex flex-wrap gap-x-2 text-sm" data-testid="mail-key-fingerprint">
          {/* Groups of four never break in the middle. */}
          {fingerprintGroups(mailKey.fingerprint).map((group, i) => (
            <span key={i} className="whitespace-nowrap">
              {group}
            </span>
          ))}
        </Mono>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-muted-foreground">
        <span>
          {t('settings.keys.created', { when: formatInstant(mailKey.createdAt, i18n.language) })}
          {' · '}
          {canEncrypt ? t('settings.keys.usage') : t('settings.keys.usageDecryptOnly')}
        </span>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void download()} loading={busy}>
            <Download />
            {t('settings.keys.download')}
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" aria-label={t('settings.keys.more')} disabled={change.isPending}>
                <MoreHorizontal />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onSelect={() => setDialog('export')}>{t('settings.keys.export')}</DropdownMenuItem>
              {signed && !mailKey.primary ? (
                <>
                  <DropdownMenuSeparator />
                  {canEncrypt && canVerify ? (
                    <DropdownMenuItem onSelect={() => apply({ kind: 'makePrimary' }, t('settings.keys.madePrimary'))}>
                      {t('settings.keys.makePrimary')}
                    </DropdownMenuItem>
                  ) : null}
                  {canVerify ? (
                    <DropdownMenuItem onSelect={() => apply({ kind: 'obsolete', on: canEncrypt }, t('settings.keys.changed'))}>
                      {canEncrypt ? t('settings.keys.markObsolete') : t('settings.keys.markNotObsolete')}
                    </DropdownMenuItem>
                  ) : null}
                  {canVerify ? (
                    <DropdownMenuItem className="text-destructive" onSelect={() => setDialog('compromised')}>
                      {t('settings.keys.markCompromised')}
                    </DropdownMenuItem>
                  ) : (
                    <DropdownMenuItem onSelect={() => apply({ kind: 'compromised', on: false }, t('settings.keys.changed'))}>
                      {t('settings.keys.markNotCompromised')}
                    </DropdownMenuItem>
                  )}
                </>
              ) : null}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
      {dialog === 'export' ? <ExportKeyDialog address={address} mailKey={mailKey} onClose={() => setDialog(null)} /> : null}
      <ConfirmDestructive
        open={dialog === 'compromised'}
        onOpenChange={(open) => setDialog(open ? 'compromised' : null)}
        title={t('settings.keys.compromisedTitle')}
        description={t('settings.keys.compromisedDescription')}
        submit={t('settings.keys.markCompromised')}
        pending={change.isPending}
        error={dialog === 'compromised' ? change.error : null}
        errorFallback={t('settings.keys.changeFailed')}
        onConfirm={() => apply({ kind: 'compromised', on: true }, t('settings.keys.changed'))}
      />
    </div>
  )
}
