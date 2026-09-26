import { ExternalLink } from 'lucide-react'
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useFolders, type FolderIndex } from '@kutup/drive-core/folders'
import type { Folder } from '@kutup/drive-core/model'
import { useMapConfig, useSaveMapPreferences } from '@kutup/map/config'
import { appUrl } from '@kutup/session/apps'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Label } from '@kutup/ui/components/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { useSaveFolder } from '../lists/lists'

const ROOT = 'root'

/** "My files / Trips / 2026": where a folder is, for choosing among them. */
function pathOf(index: FolderIndex, folder: Folder, myFiles: string): string {
  const parts: string[] = []
  let at: Folder | undefined = folder
  for (let depth = 0; at && depth < 32; depth++) {
    parts.unshift(at.isRoot ? myFiles : (at.name ?? '…'))
    at = at.parentId ? index.byId.get(at.parentId) : undefined
  }
  return parts.join(' / ')
}

/** Where new lists go, and a way to the map display settings (in the account). Over the map, at `/settings`. */
export function SettingsDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation()
  const folders = useFolders()
  const config = useMapConfig()
  const save = useSaveMapPreferences()
  const { folder: current, fellBack } = useSaveFolder()

  const choices = useMemo(() => {
    const index = folders.data
    if (!index) return []
    return index.all
      .filter((f) => f.source === 'owned' && f.key && !f.isRoot)
      .map((f) => ({ id: f.id, label: pathOf(index, f, t('home.myFiles')) }))
      .sort((a, b) => a.label.localeCompare(b.label))
  }, [folders.data, t])

  const preferences = config.data?.preferences

  function choose(value: string) {
    if (!config.data) return
    save.mutate(
      { ...config.data.preferences, saveFolderId: value === ROOT ? null : value },
      { onSuccess: () => toast.success(t('settings.saved')) },
    )
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{t('settings.title')}</DialogTitle>
          <DialogDescription className="sr-only">{t('settings.saveToHint')}</DialogDescription>
        </DialogHeader>
        {folders.isPending || config.isPending ? (
          <LoadingPanel label={t('common.loading')} />
        ) : !config.data || !folders.data || !preferences ? (
          <Alert variant="error">{t('settings.loadFailed')}</Alert>
        ) : (
      <div className="space-y-6">
      <section className="space-y-3">
        <div>
          <Label htmlFor="save-folder" className="text-base font-semibold">{t('settings.saveTo')}</Label>
          <p className="text-sm text-muted-foreground">{t('settings.saveToHint')}</p>
        </div>
        <Select value={current && !current.isRoot ? current.id : ROOT} onValueChange={choose} disabled={save.isPending}>
          <SelectTrigger id="save-folder" className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ROOT}>{t('home.myFiles')}</SelectItem>
            {choices.map((c) => (
              <SelectItem key={c.id} value={c.id}>
                {c.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {fellBack && preferences.saveFolderId ? <Alert variant="warn">{t('settings.saveFolderGone')}</Alert> : null}
        {save.error ? <Alert variant="error">{apiErrorMessage(save.error, t('settings.saveFailed'))}</Alert> : null}
      </section>
      <section className="space-y-3 border-t border-border pt-5">
        <div>
          <h2 className="text-base font-semibold">{t('settings.display')}</h2>
          <p className="text-sm text-muted-foreground">{t('settings.displayHint')}</p>
        </div>
        <Button variant="outline" asChild>
          <a href={appUrl('account', '/settings/maps')}>
            <ExternalLink /> {t('settings.openDisplay')}
          </a>
        </Button>
      </section>
      </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
