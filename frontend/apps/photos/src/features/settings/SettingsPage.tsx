import { FolderPlus, Trash2 } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { FolderIndex } from '@kutup/drive-core/folders'
import type { Folder } from '@kutup/drive-core/model'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { PageBody, PageHeader, Section } from '@kutup/ui/components/page'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { LoadingPanel } from '@kutup/ui/components/states'
import { useLibraryContext } from '../library/libraryContext'
import { DEFAULT_UPLOAD_FOLDER, folderPathName, useSavePreferences } from '../library/preferences'

/** How a folder is named in the lists: its path in My files, or its owner's for a shared one. */
function useFolderLabel(index: FolderIndex | undefined) {
  const { t } = useTranslation()
  return (folder: Folder) => {
    if (!index) return folder.name ?? ''
    if (folder.source !== 'owned') {
      return folder.ownerAccount ? t('settings.sharedBy', { folder: folder.name ?? '', owner: folder.ownerAccount }) : (folder.name ?? '')
    }
    return folderPathName(index, folder, t('info.myFiles'))
  }
}

/** Where uploads go, and which Drive folders the library shows. */
export function SettingsPage() {
  const { t } = useTranslation()
  const { preferences, index } = useLibraryContext()
  const save = useSavePreferences()
  const label = useFolderLabel(index)
  const [adding, setAdding] = useState<string>('')

  const byLabel = (a: Folder, b: Folder) => label(a).localeCompare(label(b))
  const owned = useMemo(
    () => (index?.all ?? []).filter((f) => f.source === 'owned' && f.key && !f.isRoot).sort(byLabel),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [index],
  )
  const openable = useMemo(
    () => (index?.all ?? []).filter((f) => (f.source === 'owned' || f.source === 'shared') && f.key).sort(byLabel),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [index],
  )

  if (!preferences || !index) return <LoadingPanel label={t('settings.loading')} />

  const upload = preferences.uploadFolderId ? index.byId.get(preferences.uploadFolderId) : undefined
  const added = preferences.libraryFolderIds.map((id) => index.byId.get(id)).filter((f): f is Folder => Boolean(f))
  const choices = openable.filter((f) => f.id !== upload?.id && !preferences.libraryFolderIds.includes(f.id))

  const saveWith = (next: Partial<typeof preferences>) =>
    save.mutate(
      { ...preferences, ...next },
      { onSuccess: () => toast.success(t('settings.saved')), onError: () => toast.error(t('settings.saveFailed')) },
    )

  return (
    <PageBody>
      <PageHeader title={t('settings.title')} description={t('settings.description')} />
      <Section title={t('settings.uploadTitle')} description={t('settings.uploadDescription')}>
        <div className="max-w-md space-y-2">
          <Select
            value={upload?.id ?? ''}
            onValueChange={(id) => saveWith({ uploadFolderId: id })}
            disabled={save.isPending}
          >
            <SelectTrigger aria-label={t('settings.uploadTitle')}>
              <SelectValue placeholder={t('settings.uploadDefault', { folder: DEFAULT_UPLOAD_FOLDER })} />
            </SelectTrigger>
            <SelectContent>
              {owned.map((f) => (
                <SelectItem key={f.id} value={f.id}>
                  {label(f)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {!upload ? <p className="text-sm text-muted-foreground">{t('settings.uploadNotYet', { folder: DEFAULT_UPLOAD_FOLDER })}</p> : null}
        </div>
      </Section>

      <Section title={t('settings.libraryTitle')} description={t('settings.libraryDescription')}>
        <div className="max-w-xl space-y-3">
          {added.length === 0 ? <p className="text-sm text-muted-foreground">{t('settings.libraryEmpty')}</p> : null}
          <ul className="divide-y divide-border rounded-lg border border-border">
            {added.map((folder) => (
              <li key={folder.id} className="flex items-center gap-2 px-3 py-2">
                <span className="min-w-0 flex-1 truncate text-sm">{label(folder)}</span>
                <Button
                  variant="ghost"
                  size="icon"
                  disabled={save.isPending}
                  aria-label={t('settings.remove', { folder: label(folder) })}
                  onClick={() => saveWith({ libraryFolderIds: preferences.libraryFolderIds.filter((id) => id !== folder.id) })}
                >
                  <Trash2 />
                </Button>
              </li>
            ))}
          </ul>
          <div className="flex flex-wrap items-center gap-2">
            <div className="min-w-0 flex-1">
              <Select value={adding} onValueChange={setAdding} disabled={choices.length === 0 || save.isPending}>
                <SelectTrigger aria-label={t('settings.addFolder')}>
                  <SelectValue placeholder={t('settings.chooseFolder')} />
                </SelectTrigger>
                <SelectContent>
                  {choices.map((f) => (
                    <SelectItem key={f.id} value={f.id}>
                      {label(f)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button
              variant="outline"
              disabled={!adding || save.isPending}
              onClick={() => {
                saveWith({ libraryFolderIds: [...preferences.libraryFolderIds, adding] })
                setAdding('')
              }}
            >
              <FolderPlus /> {t('settings.addFolder')}
            </Button>
          </div>
          <Alert variant="info" title={t('settings.subfoldersTitle')}>
            {t('settings.subfolders')}
          </Alert>
        </div>
      </Section>
    </PageBody>
  )
}
