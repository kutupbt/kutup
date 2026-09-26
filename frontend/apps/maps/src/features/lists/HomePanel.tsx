import { Plus, Settings, Upload, Users } from 'lucide-react'
import { useMemo, useRef, useState, type ChangeEvent } from 'react'
import { toast } from 'sonner'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate } from 'react-router-dom'
import { listTitle } from '@kutup/map/list'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { formatFileDate } from '@kutup/ui/lib/format'
import { useMapScene } from '../../app/stage'
import { PersonName } from '../people/PersonName'
import { SettingsDialog } from '../settings/SettingsDialog'
import { asPlaces, IMPORT_ACCEPT, PlaceFileTooLarge, readChosenFile, titleOf, UnreadablePlaceFile } from './files'
import { useAtlas } from './atlasContext'
import { useCreateList, useSaveFolder, type ListEntry } from './lists'
import { TitleDialog } from './TitleDialog'

/**
 * The panel's home: every place list this account can reach, newest first,
 * and all their places on the map, each list in its own colour. Clicking a
 * pin opens its list with that place chosen. `/settings` shows it with the
 * settings over it.
 */
export function HomePanel({ settings = false }: { settings?: boolean }) {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const atlas = useAtlas()
  const { lists, loading, error } = atlas
  const { folder: saveFolder, fellBack } = useSaveFolder()
  const createList = useCreateList()
  const [naming, setNaming] = useState(false)
  const [creating, setCreating] = useState(false)
  const [createError, setCreateError] = useState<unknown>(null)
  const identity = useDriveIdentity()
  const importInput = useRef<HTMLInputElement>(null)
  const [importing, setImporting] = useState(false)

  const sorted = useMemo(() => [...lists].sort((a, b) => b.file.updatedAt.localeCompare(a.file.updatedAt)), [lists])

  const markers = useMemo(
    () =>
      sorted.flatMap((entry) =>
        (atlas.placesOf(entry.file.id) ?? []).map((place) => ({
          id: `${entry.file.id}/${place.id}`,
          lat: place.lat,
          lon: place.lon,
          label: `${place.name} (${listTitle(entry.file.name ?? '')})`,
          color: atlas.colorOf(entry.file.id),
        })),
      ),
    [sorted, atlas],
  )
  useMapScene(
    // Framed once everything is in, so the view does not jump as lists arrive.
    { markers, selectedId: null, fitKey: loading || atlas.savedLoading ? null : 'home', picking: false, label: t('home.mapLabel') },
    {
      onMarkerClick: (id) => {
        const [fileId, placeId] = id.split('/')
        const place = fileId ? atlas.placesOf(fileId)?.find((p) => p.id === placeId) : undefined
        if (fileId && place) atlas.showPlace({ place, fileId })
      },
    },
  )

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
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex shrink-0 items-center gap-2 px-4 py-3">
        <h1 className="min-w-0 flex-1 font-display text-lg font-semibold">{t('home.title')}</h1>
        <Button variant="ghost" size="icon" onClick={() => void navigate('/settings')} aria-label={t('home.settings')} title={t('home.settings')}>
          <Settings />
        </Button>
      </div>
      <div className="flex shrink-0 gap-2 px-4 pb-3">
        <Button className="flex-1" onClick={() => (setCreateError(null), setNaming(true))} disabled={!saveFolder}>
          <Plus /> {t('home.new')}
        </Button>
        <Button variant="outline" onClick={() => importInput.current?.click()} disabled={!saveFolder || !identity.data || importing} loading={importing} title={t('home.importHint')}>
          <Upload /> {t('home.import')}
        </Button>
        <input ref={importInput} type="file" accept={IMPORT_ACCEPT} className="hidden" onChange={(e) => void importFile(e)} data-testid="import-file" />
      </div>
      {fellBack ? (
        <div className="px-4 pb-3">
          <Alert variant="warn">
            {t('home.saveFolderGone')} <Link to="/settings" className="underline">{t('home.changeSaveFolder')}</Link>
          </Alert>
        </div>
      ) : null}
      {error ? (
        <div className="px-4 pb-3">
          <Alert variant="error">{apiErrorMessage(error, t('home.loadFailed'))}</Alert>
        </div>
      ) : null}
      <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain border-t border-border">
        {loading && sorted.length === 0 ? (
          <LoadingPanel label={t('home.loading')} />
        ) : sorted.length === 0 ? (
          <div className="space-y-1 px-6 py-10 text-center">
            <p className="text-sm font-medium">{t('home.emptyTitle')}</p>
            <p className="text-sm text-muted-foreground">{t('home.emptyDescription')}</p>
          </div>
        ) : (
          <ul className="divide-y divide-border" aria-label={t('home.title')}>
            {sorted.map((entry) => {
              const count = atlas.placesOf(entry.file.id)?.length
              return (
                <li key={entry.file.id}>
                  <Link
                    to={entry.path}
                    className="flex items-start gap-3 px-4 py-3 outline-none transition-colors hover:bg-muted/50 focus-visible:bg-muted/70 focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
                  >
                    <span className="mt-1.5 size-3 shrink-0 rounded-full" style={{ backgroundColor: atlas.colorOf(entry.file.id) }} aria-hidden />
                    <span className="min-w-0 flex-1">
                      <span className="flex items-center gap-2">
                        <span className="min-w-0 flex-1 truncate font-medium">{listTitle(entry.file.name ?? '')}</span>
                        {entry.shared || entry.folder.ownerAccount || entry.file.shared ? (
                          <Users className="size-4 shrink-0 text-muted-foreground" aria-label={t('home.sharedMark')} />
                        ) : null}
                      </span>
                      <span className="block truncate text-xs text-muted-foreground">{where(entry)}</span>
                      <span className="block text-xs text-muted-foreground">
                        {count === undefined
                          ? t('home.updated', { date: formatFileDate(entry.file.updatedAt, i18n.language) })
                          : t('home.placesUpdated', { count, date: formatFileDate(entry.file.updatedAt, i18n.language) })}
                      </span>
                    </span>
                  </Link>
                </li>
              )
            })}
          </ul>
        )}
      </div>
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
      <SettingsDialog open={settings} onClose={() => void navigate('/')} />
    </div>
  )
}
