import { Copy, Download, ExternalLink, FolderInput, MoreHorizontal, Pencil, Trash2 } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { MoveNameTakenError } from '@kutup/drive-core/move'
import { useRenameFile, useTrashFile } from '@kutup/drive-core/mutations'
import { asNameTaken } from '@kutup/drive-core/names'
import { appUrl } from '@kutup/session/apps'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@kutup/ui/components/dropdown-menu'
import { Field } from '@kutup/ui/components/field'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { keptKeyKind, useVaultSecrets } from '../drive/secrets'
import { downloadVault, moveTargets, useDuplicateVault, useMoveVault } from '../drive/vaultActions'
import { refreshVaultFile, useVaultFiles, vaultTitle, type VaultFile } from '../drive/vaults'
import { lockVault, useVaultSession } from '../sync/openVaults'
import { GroupDialog } from './GroupDialog'

type Dialogs = 'rename' | 'move' | 'duplicate' | 'download' | 'delete' | null

/**
 * A vault's menu in the vault list, also while it is locked: rename, move,
 * duplicate, download, show in Drive, delete (to Drive's trash). Only the
 * vault's file is touched; its key, kept or not, still opens it after a
 * rename or a move.
 */
export function VaultMenu({ vault }: { vault: VaultFile }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState<Dialogs>(null)
  const title = vaultTitle(vault.file.name)
  const inDrive = vault.folder.source === 'owned' || vault.folder.source === 'shared'
  const driveUrl = appUrl('drive', vault.folder.isRoot ? '/' : `/folders/${vault.folder.id}`)
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon" aria-label={t('vaultMenu.open', { name: title })} data-testid="vault-menu">
            <MoreHorizontal />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          {vault.canEdit ? (
            <DropdownMenuItem onSelect={() => setOpen('rename')} data-testid="vault-menu-rename">
              <Pencil />
              {t('vaultMenu.rename')}
            </DropdownMenuItem>
          ) : null}
          {vault.canEdit && inDrive ? (
            <DropdownMenuItem onSelect={() => setOpen('move')} data-testid="vault-menu-move">
              <FolderInput />
              {t('vaultMenu.move')}
            </DropdownMenuItem>
          ) : null}
          {vault.folder.canUpload && inDrive ? (
            <DropdownMenuItem onSelect={() => setOpen('duplicate')} data-testid="vault-menu-duplicate">
              <Copy />
              {t('vaultMenu.duplicate')}
            </DropdownMenuItem>
          ) : null}
          <DropdownMenuItem onSelect={() => setOpen('download')} data-testid="vault-menu-download">
            <Download />
            {t('vaultMenu.download')}
          </DropdownMenuItem>
          {inDrive ? (
            <DropdownMenuItem asChild>
              <a href={driveUrl} target="_blank" rel="noreferrer" data-testid="vault-menu-drive">
                <ExternalLink />
                {t('vaultMenu.showInDrive')}
              </a>
            </DropdownMenuItem>
          ) : null}
          {vault.canEdit ? (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuItem className="text-destructive" onSelect={() => setOpen('delete')} data-testid="vault-menu-delete">
                <Trash2 />
                {t('vaultMenu.delete')}
              </DropdownMenuItem>
            </>
          ) : null}
        </DropdownMenuContent>
      </DropdownMenu>
      <RenameVault vault={vault} open={open === 'rename'} onOpenChange={(next) => setOpen(next ? 'rename' : null)} />
      <MoveVault vault={vault} open={open === 'move'} onOpenChange={(next) => setOpen(next ? 'move' : null)} />
      <DuplicateVault vault={vault} open={open === 'duplicate'} onOpenChange={(next) => setOpen(next ? 'duplicate' : null)} />
      <DownloadVault vault={vault} open={open === 'download'} onOpenChange={(next) => setOpen(next ? 'download' : null)} />
      <DeleteVault vault={vault} open={open === 'delete'} onOpenChange={(next) => setOpen(next ? 'delete' : null)} />
    </>
  )
}

/** The file's name, and the KeePass `DatabaseName` with it when the vault is open here (else at its next edit). */
function RenameVault({ vault, open, onOpenChange }: { vault: VaultFile; open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation()
  const renameFile = useRenameFile()
  const session = useVaultSession(vault.file.id)
  return (
    <GroupDialog
      open={open}
      onOpenChange={onOpenChange}
      title={t('vault.renameTitle')}
      label={t('vaults.name')}
      initial={vaultTitle(vault.file.name)}
      describeError={(failure) => (asNameTaken(failure) ? t('vault.nameTaken') : null)}
      onSubmit={async (name) => {
        const file = await refreshVaultFile(vault.folder, vault.file)
        await renameFile.mutateAsync({ folder: vault.folder, file, name: `${name}.kdbx` })
        if (session?.canEdit) {
          const view = session.getState().view
          await session.apply({ op: 'updateVault', name, description: view.description, defaultUserName: view.defaultUserName })
        }
        toast.success(t('vaultMenu.renamed'))
      }}
    />
  )
}

function MoveVault({ vault, open, onOpenChange }: { vault: VaultFile; open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation()
  const { folders } = useVaultFiles()
  const move = useMoveVault()
  const targets = useMemo(() => moveTargets(folders, vault), [folders, vault])
  const [to, setTo] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    if (open) {
      setTo('')
      setError(null)
    }
  }, [open])
  const target = targets.find((f) => f.id === to)
  const submit = async () => {
    if (!target) return
    setPending(true)
    setError(null)
    try {
      await move(vault, target)
      toast.success(t('vaultMenu.moved'))
      onOpenChange(false)
    } catch (failure) {
      setError(failure instanceof MoveNameTakenError ? t('vault.nameTaken') : t('vaultMenu.moveFailed'))
    } finally {
      setPending(false)
    }
  }
  return (
    <Dialog open={open} onOpenChange={(next) => !pending && onOpenChange(next)}>
      <DialogContent data-testid="vault-move-dialog">
        <DialogHeader>
          <DialogTitle>{t('vaultMenu.moveTitle', { name: vaultTitle(vault.file.name) })}</DialogTitle>
          <DialogDescription>{t('vaultMenu.moveDescription')}</DialogDescription>
        </DialogHeader>
        {targets.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t('vaultMenu.noFolders')}</p>
        ) : (
          <Field label={t('vaults.folder')}>
            {(field) => (
              <Select value={to} onValueChange={setTo}>
                <SelectTrigger id={field.id} data-testid="vault-move-folder">
                  <SelectValue placeholder={t('vaultMenu.chooseFolder')} />
                </SelectTrigger>
                <SelectContent>
                  {targets.map((f) => (
                    <SelectItem key={f.id} value={f.id}>
                      {f.isRoot ? t('vaults.myFiles') : (f.name ?? t('vaults.unnamedFolder'))}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </Field>
        )}
        {error ? <Alert variant="error">{error}</Alert> : null}
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
            {t('common.cancel')}
          </Button>
          <Button loading={pending} disabled={!target} onClick={() => void submit()} data-testid="vault-move-confirm">
            {t('vaultMenu.move')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** A copy in the same folder, sharing the vault's key: said before it is made. */
function DuplicateVault({ vault, open, onOpenChange }: { vault: VaultFile; open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const session = useRequiredSession()
  const secrets = useVaultSecrets()
  const duplicate = useDuplicateVault()
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    if (open) setError(null)
  }, [open])
  const submit = async () => {
    setPending(true)
    setError(null)
    try {
      const copy = await duplicate(vault, session, secrets.data)
      toast.success(copy.keyKept ? t('vaultMenu.duplicated') : t('vaultMenu.duplicatedKeyNotKept'))
      onOpenChange(false)
      void navigate(`/v/${copy.fileId}`)
    } catch {
      setError(t('vaultMenu.duplicateFailed'))
    } finally {
      setPending(false)
    }
  }
  return (
    <Dialog open={open} onOpenChange={(next) => !pending && onOpenChange(next)}>
      <DialogContent data-testid="vault-duplicate-dialog">
        <DialogHeader>
          <DialogTitle>{t('vaultMenu.duplicateTitle', { name: vaultTitle(vault.file.name) })}</DialogTitle>
          <DialogDescription>{t('vaultMenu.duplicateDescription')}</DialogDescription>
        </DialogHeader>
        <Alert variant="warn">{t('vaultMenu.duplicateSharesKey')}</Alert>
        {error ? <Alert variant="error">{error}</Alert> : null}
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
            {t('common.cancel')}
          </Button>
          <Button loading={pending} onClick={() => void submit()} data-testid="vault-duplicate-confirm">
            {t('vaultMenu.duplicate')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/**
 * The `.kdbx` as it is in Drive, for KeePassXC or a backup: said plainly
 * that it is only as safe as its key, and that the key isn't in it; with a
 * generated key, where to see it.
 */
function DownloadVault({ vault, open, onOpenChange }: { vault: VaultFile; open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const secrets = useVaultSecrets()
  const [generated, setGenerated] = useState(false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    if (!open) return
    setError(null)
    let current = true
    void keptKeyKind(session, secrets.data, vault.file.id).then((kind) => current && setGenerated(kind === 'generated' || kind === 'unknown'))
    return () => {
      current = false
    }
  }, [open, session, secrets.data, vault.file.id])
  const submit = async () => {
    setPending(true)
    setError(null)
    try {
      await downloadVault(vault)
      onOpenChange(false)
    } catch {
      setError(t('vaultMenu.downloadFailed'))
    } finally {
      setPending(false)
    }
  }
  return (
    <Dialog open={open} onOpenChange={(next) => !pending && onOpenChange(next)}>
      <DialogContent data-testid="vault-download-dialog">
        <DialogHeader>
          <DialogTitle>{t('vaultMenu.downloadTitle', { name: vaultTitle(vault.file.name) })}</DialogTitle>
          <DialogDescription>{t('vaultMenu.downloadDescription')}</DialogDescription>
        </DialogHeader>
        <Alert variant="warn">{t('vaultMenu.downloadKeyWarning')}</Alert>
        {generated ? <p className="text-sm text-muted-foreground">{t('vaultMenu.downloadGeneratedKey')}</p> : null}
        {error ? <Alert variant="error">{error}</Alert> : null}
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
            {t('common.cancel')}
          </Button>
          <Button loading={pending} onClick={() => void submit()} data-testid="vault-download-confirm">
            <Download />
            {t('vaultMenu.download')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** To Drive's trash: restorable there, and its kept key stays so it still opens then. */
function DeleteVault({ vault, open, onOpenChange }: { vault: VaultFile; open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation()
  const trash = useTrashFile()
  return (
    <ConfirmDestructive
      open={open}
      onOpenChange={onOpenChange}
      title={t('vaultMenu.deleteTitle', { name: vaultTitle(vault.file.name) })}
      description={t('vaultMenu.deleteDescription')}
      submit={t('vaultMenu.delete')}
      pending={trash.isPending}
      error={trash.error}
      errorFallback={t('vaultMenu.deleteFailed')}
      onConfirm={() => {
        void (async () => {
          await lockVault(vault.file.id)
          await trash.mutateAsync({ folder: vault.folder, file: vault.file })
          toast.success(t('vaultMenu.deleted'))
          onOpenChange(false)
        })().catch(() => undefined)
      }}
    />
  )
}
