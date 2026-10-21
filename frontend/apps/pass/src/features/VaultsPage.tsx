import { FileUp, LockKeyhole, LockKeyholeOpen, Plus, Vault } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { formatRelative } from '@kutup/ui/lib/format'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { useVaultFiles, vaultTitle, type VaultFile } from '../drive/vaults'
import { AUTO_LOCK_CHOICES, setAutoLockMinutes, setUnlockMode, useAutoLockMinutes, useUnlockMode, type AutoLockMinutes, type UnlockMode } from '../sync/autoLock'
import { useVaultSession } from '../sync/openVaults'
import { usePinStatus } from '../sync/pin'
import { SITE_ICON_MODES, useSaveSiteIconsMode, useSiteIconsMode, type SiteIconsMode } from '../sync/siteIcons'
import { CreateVaultDialog } from './CreateVaultDialog'
import { UploadVaultDialog } from './UploadVaultDialog'
import { VaultMenu } from './VaultMenu'
import { PinDialog, type PinAction } from './PinDialog'

function VaultCard({ vault }: { vault: VaultFile }) {
  const { t, i18n } = useTranslation()
  const open = Boolean(useVaultSession(vault.file.id))
  const where = vault.folder.isRoot ? t('vaults.myFiles') : (vault.folder.name ?? t('vaults.unnamedFolder'))
  return (
    <li className="flex items-center gap-1">
      <Link
        to={`/v/${vault.file.id}`}
        className="flex min-w-0 flex-1 items-center gap-4 rounded-lg border border-border bg-card p-4 transition-colors hover:bg-accent/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <span className="grid size-10 shrink-0 place-items-center rounded-md bg-primary/10 text-primary">
          <Vault className="size-5" aria-hidden />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate font-medium">{vaultTitle(vault.file.name)}</span>
          <span className="block truncate text-xs text-muted-foreground">
            {vault.owner ? t('vaults.sharedBy', { owner: vault.owner, folder: where }) : t('vaults.inFolder', { folder: where })}
            {' · '}
            {t('vaults.changed', { when: formatRelative(vault.file.updatedAt, i18n.language) })}
            {vault.canEdit ? '' : ` · ${t('vaults.readOnly')}`}
          </span>
        </span>
        {open ? (
          <LockKeyholeOpen className="size-4 text-muted-foreground" aria-label={t('vaults.unlocked')} />
        ) : (
          <LockKeyhole className="size-4 text-muted-foreground" aria-label={t('vaults.locked')} />
        )}
      </Link>
      <VaultMenu vault={vault} />
    </li>
  )
}

/** How long open vaults stay unlocked without use, on this device. */
function AutoLockSetting() {
  const { t } = useTranslation()
  const minutes = useAutoLockMinutes()
  const mode = useUnlockMode()
  const pinSet = usePinStatus().data === true
  const [pinAction, setPinAction] = useState<PinAction | null>(null)
  return (
    <>
    <section className="mt-8 max-w-3xl space-y-1.5" aria-labelledby="auto-lock-label">
      <h2 id="auto-lock-label" className="text-sm font-medium">
        {t('autoLock.label')}
      </h2>
      <p className="text-xs text-muted-foreground">{t('autoLock.description')}</p>
      <Select value={String(minutes)} onValueChange={(value) => setAutoLockMinutes(Number(value) as AutoLockMinutes)}>
        <SelectTrigger className="w-56" aria-labelledby="auto-lock-label">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {AUTO_LOCK_CHOICES.map((choice) => (
            <SelectItem key={choice} value={String(choice)}>
              {choice === 0 ? t('autoLock.never') : choice >= 60 ? t('autoLock.hours', { count: choice / 60 }) : t('autoLock.minutes', { count: choice })}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </section>
    <section className="mt-6 max-w-3xl space-y-1.5" aria-labelledby="unlock-mode-label">
      <h2 id="unlock-mode-label" className="text-sm font-medium">
        {t('unlockMode.label')}
      </h2>
      <p className="text-xs text-muted-foreground">{t('unlockMode.description')}</p>
      <Select
        value={mode}
        onValueChange={(value) => {
          // The PIN mode needs a PIN: set one first.
          if (value === 'pin' && !pinSet) setPinAction('set')
          else setUnlockMode(value as UnlockMode)
        }}
      >
        <SelectTrigger className="w-56" aria-labelledby="unlock-mode-label">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="password">{t('unlockMode.password')}</SelectItem>
          <SelectItem value="pin">{t('unlockMode.pin')}</SelectItem>
          <SelectItem value="click">{t('unlockMode.click')}</SelectItem>
        </SelectContent>
      </Select>
      {pinSet ? (
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <span className="text-xs text-muted-foreground">{t('pin.isSet')}</span>
          <Button size="sm" variant="outline" onClick={() => setPinAction('change')}>
            {t('pin.change')}
          </Button>
          <Button size="sm" variant="outline" onClick={() => setPinAction('remove')}>
            {t('pin.remove')}
          </Button>
        </div>
      ) : null}
      <PinDialog
        action={pinAction}
        onOpenChange={(open) => !open && setPinAction(null)}
        onDone={(action) => {
          if (action === 'remove') {
            if (mode === 'pin') setUnlockMode('password')
          } else setUnlockMode('pin')
        }}
      />
    </section>
    </>
  )
}

/** How entries get their website's icon, for the whole account. */
function SiteIconsSetting() {
  const { t } = useTranslation()
  const mode = useSiteIconsMode()
  const save = useSaveSiteIconsMode()
  return (
    <section className="mt-6 max-w-3xl space-y-1.5" aria-labelledby="site-icons-label">
      <h2 id="site-icons-label" className="text-sm font-medium">
        {t('siteIcons.label')}
      </h2>
      <p className="text-xs text-muted-foreground">{mode ? t(`siteIcons.about.${mode}`) : t('siteIcons.description')}</p>
      <Select
        value={mode}
        disabled={!mode}
        onValueChange={(value) => void save(value as SiteIconsMode).catch(() => toast.error(t('siteIcons.saveFailed')))}
      >
        <SelectTrigger className="w-72" aria-labelledby="site-icons-label">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {SITE_ICON_MODES.map((choice) => (
            <SelectItem key={choice} value={choice}>
              {t(`siteIcons.${choice}`)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </section>
  )
}

/** Every vault the account can open, and a way to make one. */
export function VaultsPage({ creating: startCreating = false }: { creating?: boolean }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const { vaults, loading, error } = useVaultFiles()
  const [creating, setCreating] = useState(startCreating)
  const [uploading, setUploading] = useState(false)
  const folderId = startCreating ? params.get('folder') : null
  if (loading) return <LoadingPanel label={t('vaults.loading')} />
  return (
    <PageBody className="px-4 py-6 md:px-8 md:py-8">
      <PageHeader
        title={t('vaults.title')}
        description={t('vaults.description')}
        actions={
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" onClick={() => setUploading(true)} data-testid="vault-upload">
              <FileUp />
              {t('upload.open')}
            </Button>
            <Button onClick={() => setCreating(true)}>
              <Plus />
              {t('vaults.new')}
            </Button>
          </div>
        }
      />
      {error ? <Alert variant="error">{t('vaults.loadFailed')}</Alert> : null}
      {vaults.length === 0 && !error ? (
        <EmptyState
          title={t('vaults.emptyTitle')}
          description={t('vaults.emptyDescription')}
          action={
            <div className="flex flex-wrap justify-center gap-2">
              <Button variant="outline" onClick={() => setUploading(true)}>
                <FileUp />
                {t('upload.open')}
              </Button>
              <Button onClick={() => setCreating(true)}>
                <Plus />
                {t('vaults.new')}
              </Button>
            </div>
          }
        />
      ) : (
        <ul className="grid max-w-3xl gap-3" aria-label={t('vaults.title')}>
          {vaults.map((v) => (
            <VaultCard key={v.file.id} vault={v} />
          ))}
        </ul>
      )}
      <AutoLockSetting />
      <SiteIconsSetting />
      <p className="mt-8 max-w-3xl text-xs text-muted-foreground">{t('vaults.keepassNote')}</p>
      <UploadVaultDialog open={uploading} onOpenChange={setUploading} />
      <CreateVaultDialog
        open={creating}
        folderId={folderId}
        onOpenChange={(open) => {
          setCreating(open)
          // Closed without making one: back to the list, not this address again.
          if (!open && startCreating) void navigate('/', { replace: true })
        }}
      />
    </PageBody>
  )
}
