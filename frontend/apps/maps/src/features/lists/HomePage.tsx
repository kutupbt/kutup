import { MapPin, Plus, Upload, Users } from 'lucide-react'
import { useMemo, useRef, useState, type ChangeEvent } from 'react'
import { toast } from 'sonner'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate } from 'react-router-dom'
import { listTitle } from '@kutup/map/list'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { formatFileDate } from '@kutup/ui/lib/format'
import { PersonName } from '../people/PersonName'
import { asPlaces, IMPORT_ACCEPT, PlaceFileTooLarge, readChosenFile, titleOf, UnreadablePlaceFile } from './files'
import { useCreateList, useLists, useSaveFolder, type ListEntry } from './lists'
import { TitleDialog } from './TitleDialog'

/** Every place list this account can reach, newest first. */
export function HomePage() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const { lists, loading, error } = useLists()
  const { folder: saveFolder, fellBack } = useSaveFolder()
  const createList = useCreateList()
  const [naming, setNaming] = useState(false)
  const [creating, setCreating] = useState(false)
  const [createError, setCreateError] = useState<unknown>(null)
  const identity = useDriveIdentity()
  const importInput = useRef<HTMLInputElement>(null)
  const [importing, setImporting] = useState(false)

  const sorted = useMemo(() => [...lists].sort((a, b) => b.file.updatedAt.localeCompare(a.file.updatedAt)), [lists])

  async function create(title: string) {
    if (!saveFolder) return
    setCreating(true)
    setCreateError(null)
    try {
      const path = await createList(saveFolder, title)
      setNaming(false)
      void navigate(path)
    } catch (e) {
      setCreateError(e)
    } finally {
      setCreating(false)
    }
  }

  /** A KML, GPX or Kutup list file becomes a new map, read on this device. */
  async function importFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file || !saveFolder || !identity.data) return
    setImporting(true)
    try {
      const imported = await readChosenFile(file, (n) => t('home.importPlaceName', { n }))
      if (imported.places.length === 0) {
        toast.error(t('home.importEmpty'))
        return
      }
      const path = await createList(saveFolder, titleOf(imported, file), asPlaces(imported, identity.data.account))
      toast.success(
        imported.skipped > 0
          ? t('home.importedSkipped', { count: imported.places.length, skipped: imported.skipped })
          : t('home.imported', { count: imported.places.length }),
      )
      void navigate(path)
    } catch (error) {
      toast.error(
        error instanceof UnreadablePlaceFile
          ? t('home.importUnreadable')
          : error instanceof PlaceFileTooLarge
            ? t('home.importTooLarge')
            : t('home.importFailed'),
      )
    } finally {
      setImporting(false)
    }
  }

  const where = (entry: ListEntry) => {
    if (entry.shared) return <PersonName account={entry.shared.ownerAccount} format={(name) => t('home.from', { name })} />
    if (entry.folder.ownerAccount) return <PersonName account={entry.folder.ownerAccount} format={(name) => t('home.inShared', { folder: entry.folder.name ?? '', name })} />
    return t('home.in', { folder: entry.folder.isRoot ? t('home.myFiles') : (entry.folder.name ?? t('home.encrypted')) })
  }

  return (
    <div className="mx-auto w-full max-w-5xl space-y-5 px-4 py-6 md:px-6">
      <div className="flex flex-wrap items-center gap-3">
        <div className="min-w-0 flex-1">
          <h1 className="font-display text-2xl font-semibold tracking-tight">{t('home.title')}</h1>
          <p className="text-sm text-muted-foreground">{t('home.description')}</p>
        </div>
        <Button variant="outline" onClick={() => importInput.current?.click()} disabled={!saveFolder || !identity.data || importing} loading={importing} title={t('home.importHint')}>
          <Upload /> {t('home.import')}
        </Button>
        <Button onClick={() => (setCreateError(null), setNaming(true))} disabled={!saveFolder}>
          <Plus /> {t('home.new')}
        </Button>
        <input ref={importInput} type="file" accept={IMPORT_ACCEPT} className="hidden" onChange={(e) => void importFile(e)} data-testid="import-file" />
      </div>
      {fellBack ? (
        <Alert variant="warn">
          {t('home.saveFolderGone')} <Link to="/settings" className="underline">{t('home.changeSaveFolder')}</Link>
        </Alert>
      ) : null}
      {error ? <Alert variant="error">{apiErrorMessage(error, t('home.loadFailed'))}</Alert> : null}
      {loading && sorted.length === 0 ? (
        <LoadingPanel label={t('home.loading')} />
      ) : sorted.length === 0 ? (
        <EmptyState
          title={t('home.emptyTitle')}
          description={t('home.emptyDescription')}
          action={
            <Button onClick={() => setNaming(true)} disabled={!saveFolder}>
              <Plus /> {t('home.new')}
            </Button>
          }
        />
      ) : (
        <ul className="grid grid-cols-[repeat(auto-fill,minmax(15rem,1fr))] gap-3">
          {sorted.map((entry) => (
            <li key={entry.file.id}>
              <Link
                to={entry.path}
                className="flex h-full flex-col gap-2 rounded-xl border border-border bg-card p-4 outline-none transition-colors hover:border-primary/40 hover:bg-muted/40 focus-visible:ring-2 focus-visible:ring-ring"
              >
                <span className="flex items-center gap-2">
                  <MapPin className="size-5 shrink-0 text-primary" aria-hidden />
                  <span className="min-w-0 flex-1 truncate font-medium">{listTitle(entry.file.name ?? '')}</span>
                  {entry.shared || entry.folder.ownerAccount || entry.file.shared ? (
                    <Users className="size-4 shrink-0 text-muted-foreground" aria-label={t('home.sharedMark')} />
                  ) : null}
                </span>
                <span className="truncate text-xs text-muted-foreground">{where(entry)}</span>
                <span className="text-xs text-muted-foreground">{t('home.updated', { date: formatFileDate(entry.file.updatedAt, i18n.language) })}</span>
              </Link>
            </li>
          ))}
        </ul>
      )}
      <TitleDialog
        open={naming}
        title={t('home.newTitle')}
        description={
          saveFolder
            ? t('home.newDescription', { folder: saveFolder.isRoot ? t('home.myFiles') : (saveFolder.name ?? '') })
            : undefined
        }
        initial={t('home.untitled')}
        submit={t('home.create')}
        pending={creating}
        error={createError}
        onClose={() => setNaming(false)}
        onSubmit={(title) => void create(title)}
      />
    </div>
  )
}
