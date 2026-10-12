import { LockKeyhole, LockKeyholeOpen, Plus, Vault } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { formatRelative } from '@kutup/ui/lib/format'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { useVaultFiles, vaultTitle, type VaultFile } from '../drive/vaults'
import { AUTO_LOCK_CHOICES, setAutoLockMinutes, useAutoLockMinutes, type AutoLockMinutes } from '../sync/autoLock'
import { useVaultSession } from '../sync/openVaults'
import { CreateVaultDialog } from './CreateVaultDialog'

function VaultCard({ vault }: { vault: VaultFile }) {
  const { t, i18n } = useTranslation()
  const open = Boolean(useVaultSession(vault.file.id))
  const where = vault.folder.isRoot ? t('vaults.myFiles') : (vault.folder.name ?? t('vaults.unnamedFolder'))
  return (
    <li>
      <Link
        to={`/v/${vault.file.id}`}
        className="flex items-center gap-4 rounded-lg border border-border bg-card p-4 transition-colors hover:bg-accent/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
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
    </li>
  )
}

/** How long open vaults stay unlocked without use, on this device. */
function AutoLockSetting() {
  const { t } = useTranslation()
  const minutes = useAutoLockMinutes()
  return (
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
  )
}

/** Every vault the account can open, and a way to make one. */
export function VaultsPage() {
  const { t } = useTranslation()
  const { vaults, loading, error } = useVaultFiles()
  const [creating, setCreating] = useState(false)
  if (loading) return <LoadingPanel label={t('vaults.loading')} />
  return (
    <PageBody className="px-4 py-6 md:px-8 md:py-8">
      <PageHeader
        title={t('vaults.title')}
        description={t('vaults.description')}
        actions={
          <Button onClick={() => setCreating(true)}>
            <Plus />
            {t('vaults.new')}
          </Button>
        }
      />
      {error ? <Alert variant="error">{t('vaults.loadFailed')}</Alert> : null}
      {vaults.length === 0 && !error ? (
        <EmptyState
          title={t('vaults.emptyTitle')}
          description={t('vaults.emptyDescription')}
          action={
            <Button onClick={() => setCreating(true)}>
              <Plus />
              {t('vaults.new')}
            </Button>
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
      <p className="mt-8 max-w-3xl text-xs text-muted-foreground">{t('vaults.keepassNote')}</p>
      <CreateVaultDialog open={creating} onOpenChange={setCreating} />
    </PageBody>
  )
}
