import { useQueries, useQuery } from '@tanstack/react-query'
import { Download, KeyRound, MoreHorizontal, Settings2, Upload } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { armorMailPublicKey, fromBase64, inspectExternalMailKey } from '@kutup/crypto'
import { describeExternalMailKeyDetails, type ExternalMailKeyDetails } from '@kutup/crypto/mailKey'
import { useSaveContact } from '@kutup/contacts-core/api'
import { formatFingerprint, keysFor, pgpFor, type Contact, type ContactEmailPgp, type ContactKey } from '@kutup/contacts-core/model'
import { outsideKey, type OutsideKey } from '@kutup/mail-core/keys'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@kutup/ui/components/dropdown-menu'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@kutup/ui/components/table'
import { formatInstant } from '@kutup/ui/lib/format'

/** Largest key file read (kutup-crypto `MAX_EXTERNAL_KEY_LEN`). */
const MAX_KEY_FILE = 256 * 1024

/** One key in the table: trusted (in Contacts), found online, or both. */
interface KeyRow {
  fingerprint: string
  publicKey: string
  trusted: boolean
  /** Where it was found online; none for a key the person uploaded. */
  source?: OutsideKey['source']
}

/** The keys Kutup finds online for an address (WKD, Proton, keys.openpgp.org), each checked in the browser. */
function useFoundKeys(address: string) {
  return useQuery({
    queryKey: ['contacts', 'found-keys', address],
    staleTime: 15 * 60_000,
    retry: false,
    queryFn: () => outsideKey(address),
  })
}

/** Type, dates and state of each key, for the table. */
function useDetails(rows: KeyRow[], address: string) {
  const details = useQueries({
    queries: rows.map((row) => ({
      queryKey: ['contacts', 'key-details', address, row.fingerprint],
      staleTime: 60 * 60_000,
      queryFn: () => describeExternalMailKeyDetails(fromBase64(row.publicKey), address),
    })),
  })
  return new Map(rows.map((row, i) => [row.fingerprint, details[i]?.data]))
}

const STATE_ORDER: Record<ExternalMailKeyDetails['state'], number> = { usable: 0, cannotEncrypt: 1, otherAddress: 1, expired: 2, revoked: 3 }

/**
 * The line under one of a contact's outside addresses: what protects mail to
 * it, and the way into its settings (Proton's "Email settings").
 */
export function EmailKeys({ contact, address }: { contact: Contact; address: string }) {
  const { t } = useTranslation()
  const lower = address.trim().toLowerCase()
  const [open, setOpen] = useState(false)
  const trusted = keysFor(contact.draft, lower)
  const found = useFoundKeys(lower)
  const pgp = pgpFor(contact.draft, lower)
  const summary =
    pgp.encrypt === false
      ? t('keys.summaryOff')
      : trusted.length
        ? t('keys.summaryTrusted', { count: trusted.length })
        : found.data
          ? t(`keys.summaryFound.${found.data.source}`)
          : found.isPending
            ? null
            : t('keys.summaryNone')
  return (
    <>
      {summary ? (
        <Badge variant={pgp.encrypt === false || (!trusted.length && !found.data) ? 'neutral' : 'ok'} aria-label={t('keys.label', { address: lower })}>
          <KeyRound className="size-3" aria-hidden />
          {summary}
        </Badge>
      ) : null}
      <Button variant="ghost" size="sm" onClick={() => setOpen(true)}>
        <Settings2 />
        {t('keys.settings')}
      </Button>
      {open ? <EmailSettingsDialog contact={contact} address={lower} found={found.data ?? null} foundPending={found.isPending} onClose={() => setOpen(false)} /> : null}
    </>
  )
}

/**
 * Proton's "Edit email settings" (ContactEmailSettingsModal): the keys found
 * online and the trusted ones in one table (ContactKeysTable), and Encrypt,
 * Sign and scheme for the address (ContactPGPSettings). Saving stores the
 * trusted keys in order and the preferences; found keys nobody trusted are
 * not stored, they are looked up again (docs/plans/contact-keys.md).
 */
function EmailSettingsDialog({
  contact,
  address,
  found,
  foundPending,
  onClose,
}: {
  contact: Contact
  address: string
  found: OutsideKey | null
  foundPending: boolean
  onClose: () => void
}) {
  const { t, i18n } = useTranslation()
  const save = useSaveContact()
  const file = useRef<HTMLInputElement>(null)
  const [trusted, setTrusted] = useState<ContactKey[]>(() => keysFor(contact.draft, address))
  const [pgp, setPgp] = useState<ContactEmailPgp>(() => pgpFor(contact.draft, address))
  const foundKeys = useMemo(() => found?.keys ?? [], [found])

  const rows: KeyRow[] = useMemo(() => {
    const byFingerprint = new Map<string, KeyRow>()
    for (const key of trusted) byFingerprint.set(key.fingerprint, { fingerprint: key.fingerprint, publicKey: key.publicKey, trusted: true })
    for (const key of foundKeys) {
      const row = byFingerprint.get(key.fingerprint)
      byFingerprint.set(key.fingerprint, row ? { ...row, source: found?.source } : { fingerprint: key.fingerprint, publicKey: key.publicKey, trusted: false, source: found?.source })
    }
    return [...byFingerprint.values()]
  }, [trusted, foundKeys, found?.source])
  const details = useDetails(rows, address)
  // Trusted first in their order, then found; usable before expired and revoked (the history at the bottom).
  const sorted = [...rows].sort((a, b) => {
    const state = (row: KeyRow) => STATE_ORDER[details.get(row.fingerprint)?.state ?? 'usable']
    if (state(a) !== state(b)) return state(a) - state(b)
    if (a.trusted !== b.trusted) return a.trusted ? -1 : 1
    const order = (row: KeyRow) => trusted.findIndex((k) => k.fingerprint === row.fingerprint)
    return order(a) - order(b)
  })
  const usable = (row: KeyRow) => details.get(row.fingerprint)?.state === 'usable'
  // The key mail goes to: the first trusted one that can encrypt, else a found one.
  const sending = trusted.length ? sorted.find((row) => row.trusted && usable(row)) : sorted.find((row) => row.source && usable(row))
  const hasKeys = rows.length > 0
  const encrypt = pgp.encrypt ?? hasKeys
  // Proton's canUploadKeys: only when nothing was found online.
  const canUpload = !foundPending && foundKeys.length === 0
  // Found keys that disagree with the trusted ones: trust one of them to keep encrypting.
  const askToTrust = trusted.length > 0 && foundKeys.length > 0 && !foundKeys.some((key) => trusted.some((k) => k.fingerprint === key.fingerprint))
  const allTrustedUnusable = trusted.length > 0 && !sorted.some((row) => row.trusted && usable(row))

  useEffect(() => {
    // Encrypting signs anyway (Proton): the Sign choice waits until Encrypt is off.
    if (encrypt && pgp.sign === false) setPgp((now) => ({ ...now, sign: undefined }))
  }, [encrypt, pgp.sign])

  function trust(row: KeyRow) {
    setTrusted((now) => [{ address, publicKey: row.publicKey, fingerprint: row.fingerprint }, ...now.filter((k) => k.fingerprint !== row.fingerprint)])
  }
  function untrust(row: KeyRow) {
    setTrusted((now) => now.filter((k) => k.fingerprint !== row.fingerprint))
  }
  function sendWith(row: KeyRow) {
    setTrusted((now) => [...now.filter((k) => k.fingerprint === row.fingerprint), ...now.filter((k) => k.fingerprint !== row.fingerprint)])
  }
  async function download(row: KeyRow) {
    const armored = await armorMailPublicKey(row.publicKey)
    const url = URL.createObjectURL(new Blob([armored], { type: 'application/pgp-keys' }))
    const link = document.createElement('a')
    link.href = url
    link.download = `publickey - ${address} - 0x${row.fingerprint.slice(0, 8).toUpperCase()}.asc`
    link.click()
    URL.revokeObjectURL(url)
  }
  async function upload(chosen: File | undefined) {
    if (!chosen) return
    try {
      if (chosen.size > MAX_KEY_FILE) throw new Error('too large')
      const info = await inspectExternalMailKey(new Uint8Array(await chosen.arrayBuffer()), address)
      if (trusted.some((k) => k.fingerprint === info.fingerprint)) toast.info(t('keys.duplicate'))
      setTrusted((now) => [{ address, publicKey: info.publicKey, fingerprint: info.fingerprint }, ...now.filter((k) => k.fingerprint !== info.fingerprint)])
    } catch {
      toast.error(t('keys.noUsableKey', { address }))
    }
  }

  function submit() {
    const others = contact.draft.keys.filter((key) => key.address !== address)
    const cleaned: ContactEmailPgp = {}
    if (pgp.encrypt !== undefined) cleaned.encrypt = pgp.encrypt
    if (!encrypt && pgp.sign !== undefined) cleaned.sign = pgp.sign
    if (pgp.scheme) cleaned.scheme = pgp.scheme
    const draft = {
      ...contact.draft,
      keys: [...others, ...trusted],
      emails: contact.draft.emails.map((email) =>
        email.address.trim().toLowerCase() === address ? { ...email, pgp: Object.keys(cleaned).length ? cleaned : undefined } : email,
      ),
    }
    save.mutate(
      { draft, existing: contact },
      {
        onSuccess: () => {
          toast.success(t('keys.saved'))
          onClose()
        },
        onError: () => toast.error(t('keys.saveFailed')),
      },
    )
  }

  const choice = (value: boolean | undefined) => (value === undefined ? 'default' : value ? 'yes' : 'no')
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <DialogTitle>{t('keys.dialogTitle')}</DialogTitle>
          <DialogDescription>{address}</DialogDescription>
        </DialogHeader>
        <input
          ref={file}
          type="file"
          accept=".asc,.pgp,.gpg,.key,application/pgp-keys"
          className="hidden"
          aria-hidden
          tabIndex={-1}
          onChange={(e) => {
            void upload(e.target.files?.[0])
            e.target.value = ''
          }}
        />
        <div className="space-y-4">
          {!hasKeys && !foundPending ? <Alert>{t('keys.setupHint')}</Alert> : null}
          {askToTrust ? <Alert variant="warn">{t('keys.askToTrust')}</Alert> : null}
          {allTrustedUnusable ? <Alert variant="warn">{t('keys.allUnusable')}</Alert> : null}

          <label className="flex items-start gap-3">
            <Checkbox className="mt-0.5" checked={encrypt} disabled={!hasKeys} onCheckedChange={(on) => setPgp((now) => ({ ...now, encrypt: on === true }))} />
            <span>
              <span className="block text-sm font-medium">{t('keys.encrypt')}</span>
              <span className="block text-sm text-muted-foreground">{t('keys.encryptHint')}</span>
            </span>
          </label>

          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1">
              <label htmlFor="email-sign" className="text-sm font-medium">
                {t('keys.sign')}
              </label>
              <Select
                value={encrypt ? 'yes' : choice(pgp.sign)}
                disabled={encrypt}
                onValueChange={(value) => setPgp((now) => ({ ...now, sign: value === 'default' ? undefined : value === 'yes' }))}
              >
                <SelectTrigger id="email-sign" aria-label={t('keys.sign')}>
                  <SelectValue placeholder={t('keys.sign')} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="default">{t('keys.useDefault')}</SelectItem>
                  <SelectItem value="yes">{t('keys.signYes')}</SelectItem>
                  <SelectItem value="no">{t('keys.signNo')}</SelectItem>
                </SelectContent>
              </Select>
              {encrypt ? <p className="text-xs text-muted-foreground">{t('keys.signForced')}</p> : null}
            </div>
            <div className="space-y-1">
              <label htmlFor="email-scheme" className="text-sm font-medium">
                {t('keys.scheme')}
              </label>
              <Select value={pgp.scheme ?? 'default'} onValueChange={(value) => setPgp((now) => ({ ...now, scheme: value === 'default' ? undefined : (value as ContactEmailPgp['scheme']) }))}>
                <SelectTrigger id="email-scheme" aria-label={t('keys.scheme')}>
                  <SelectValue placeholder={t('keys.scheme')} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="default">{t('keys.useDefault')}</SelectItem>
                  <SelectItem value="pgp_mime">PGP/MIME</SelectItem>
                  <SelectItem value="inline">{t('keys.inline')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <section className="space-y-2" aria-label={t('keys.tableLabel')}>
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-sm font-medium">{t('keys.tableTitle')}</h3>
              {canUpload ? (
                <Button variant="outline" size="sm" onClick={() => file.current?.click()}>
                  <Upload />
                  {t('keys.upload')}
                </Button>
              ) : null}
            </div>
            {foundPending ? (
              <p className="text-sm text-muted-foreground">{t('keys.looking')}</p>
            ) : rows.length === 0 ? (
              <p className="text-sm text-muted-foreground">{t('keys.noneFound')}</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('keys.fingerprint')}</TableHead>
                    <TableHead>{t('keys.created')}</TableHead>
                    <TableHead>{t('keys.expires')}</TableHead>
                    <TableHead>{t('keys.type')}</TableHead>
                    <TableHead>{t('keys.status')}</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sorted.map((row) => {
                    const info = details.get(row.fingerprint)
                    const state = info?.state
                    return (
                      <TableRow key={row.fingerprint} data-fingerprint={row.fingerprint}>
                        <TableCell>
                          <code className="text-xs" title={formatFingerprint(row.fingerprint)}>
                            {formatFingerprint(row.fingerprint).slice(-19)}
                          </code>
                        </TableCell>
                        <TableCell className="whitespace-nowrap text-sm">{info ? formatInstant(new Date(info.createdAt * 1000).toISOString(), i18n.language) : '…'}</TableCell>
                        <TableCell className="whitespace-nowrap text-sm">
                          {info?.expiresAt ? formatInstant(new Date(info.expiresAt * 1000).toISOString(), i18n.language) : info ? t('keys.never') : '…'}
                        </TableCell>
                        <TableCell className="whitespace-nowrap text-sm">{info?.algorithm ?? '…'}</TableCell>
                        <TableCell>
                          <span className="flex flex-wrap gap-1">
                            {row.source ? <Badge variant="neutral">{t(`keys.source.${row.source}`)}</Badge> : null}
                            {row.trusted ? <Badge variant="ok">{t('keys.trusted')}</Badge> : null}
                            {encrypt && sending?.fingerprint === row.fingerprint ? <Badge>{t('keys.usedForSending')}</Badge> : null}
                            {state === 'expired' ? <Badge variant="warn">{t('keys.expired')}</Badge> : null}
                            {state === 'revoked' ? <Badge variant="danger">{t('keys.revoked')}</Badge> : null}
                            {state === 'otherAddress' || state === 'cannotEncrypt' ? <Badge variant="warn">{t('keys.unusable')}</Badge> : null}
                          </span>
                        </TableCell>
                        <TableCell className="text-right">
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="icon" className="size-8" aria-label={t('keys.actions', { fingerprint: row.fingerprint.slice(-8).toUpperCase() })}>
                                <MoreHorizontal />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onSelect={() => void download(row)}>
                                <Download />
                                {t('keys.download')}
                              </DropdownMenuItem>
                              {!row.trusted && row.source && state !== 'revoked' ? <DropdownMenuItem onSelect={() => trust(row)}>{t('keys.trust')}</DropdownMenuItem> : null}
                              {row.trusted && row.source ? <DropdownMenuItem onSelect={() => untrust(row)}>{t('keys.untrust')}</DropdownMenuItem> : null}
                              {row.trusted && usable(row) && sending?.fingerprint !== row.fingerprint ? (
                                <DropdownMenuItem onSelect={() => sendWith(row)}>{t('keys.useForSending')}</DropdownMenuItem>
                              ) : null}
                              {row.trusted && !row.source ? (
                                <DropdownMenuItem destructive onSelect={() => untrust(row)}>
                                  {t('keys.remove')}
                                </DropdownMenuItem>
                              ) : null}
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
            )}
          </section>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button onClick={submit} disabled={save.isPending}>
            {t('common.save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
