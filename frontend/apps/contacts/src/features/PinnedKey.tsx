import { useQuery } from '@tanstack/react-query'
import { KeyRound, Upload, X } from 'lucide-react'
import { useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { fromBase64, inspectExternalMailKey } from '@kutup/crypto'
import { usePinKey, useSaveContact } from '@kutup/contacts-core/api'
import { formatFingerprint, type Contact } from '@kutup/contacts-core/model'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'

/** Largest key file read (kutup-crypto `MAX_EXTERNAL_KEY_LEN`). */
const MAX_KEY_FILE = 256 * 1024

/**
 * The OpenPGP key pinned for one of a contact's outside addresses
 * (docs/plans/mail.md, C3): Mail encrypts to it and checks signatures with
 * it. Added from a key file here, or from a message in Mail.
 */
export function PinnedKey({ contact, address }: { contact: Contact; address: string }) {
  const { t } = useTranslation()
  const lower = address.trim().toLowerCase()
  const key = contact.draft.keys.find((k) => k.address === lower)
  const pin = usePinKey()
  const save = useSaveContact()
  const file = useRef<HTMLInputElement>(null)
  const usable = useQuery({
    queryKey: ['contacts', 'key-usable', lower, key?.fingerprint],
    enabled: !!key,
    staleTime: 60 * 60_000,
    queryFn: () =>
      inspectExternalMailKey(fromBase64(key!.publicKey), lower).then(
        () => true,
        () => false,
      ),
  })

  async function pick(chosen: File | undefined) {
    if (!chosen) return
    if (chosen.size > MAX_KEY_FILE) {
      toast.error(t('keys.noUsableKey', { address: lower }))
      return
    }
    let publicKey: string
    try {
      publicKey = (await inspectExternalMailKey(new Uint8Array(await chosen.arrayBuffer()), lower)).publicKey
    } catch {
      toast.error(t('keys.noUsableKey', { address: lower }))
      return
    }
    pin.mutate(
      { address: lower, publicKey },
      {
        onSuccess: () => toast.success(t('keys.pinned', { address: lower })),
        onError: () => toast.error(t('keys.saveFailed')),
      },
    )
  }

  function remove() {
    const draft = { ...contact.draft, keys: contact.draft.keys.filter((k) => k.address !== lower) }
    save.mutate(
      { draft, existing: contact },
      {
        onSuccess: () => toast.success(t('keys.removed', { address: lower })),
        onError: () => toast.error(t('keys.saveFailed')),
      },
    )
  }

  const input = (
    <input
      ref={file}
      type="file"
      accept=".asc,.pgp,.gpg,.key,application/pgp-keys"
      className="hidden"
      aria-hidden
      tabIndex={-1}
      onChange={(e) => {
        void pick(e.target.files?.[0])
        e.target.value = ''
      }}
    />
  )

  if (!key) {
    return (
      <>
        {input}
        <Button variant="ghost" size="sm" disabled={pin.isPending} onClick={() => file.current?.click()}>
          <KeyRound />
          {t('keys.add')}
        </Button>
      </>
    )
  }

  return (
    <div className="flex w-full flex-wrap items-center gap-2 rounded-md border border-border px-3 py-2 text-sm" aria-label={t('keys.label', { address: lower })}>
      {input}
      <KeyRound className="size-4 shrink-0 text-muted-foreground" aria-hidden />
      <span className="min-w-0 flex-1">
        <span className="block font-medium">{t('keys.title')}</span>
        <code className="block break-all text-xs text-muted-foreground">{formatFingerprint(key.fingerprint)}</code>
      </span>
      {usable.data === false ? (
        <Badge variant="warn" title={t('keys.unusableHint')}>
          {t('keys.unusable')}
        </Badge>
      ) : usable.data ? (
        <Badge variant="ok" title={t('keys.trustedHint')}>{t('keys.trusted')}</Badge>
      ) : null}
      <Button variant="ghost" size="sm" disabled={pin.isPending} onClick={() => file.current?.click()}>
        <Upload />
        {t('keys.replace')}
      </Button>
      <Button variant="ghost" size="sm" disabled={save.isPending} onClick={remove}>
        <X />
        {t('keys.remove')}
      </Button>
    </div>
  )
}
