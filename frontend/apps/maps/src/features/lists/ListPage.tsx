import { useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Download, Eye, FileDown, MapPin, MessageSquare, MoreHorizontal, Pencil, Plus, Trash2, Upload, UserPlus, Users, X } from 'lucide-react'
import { lazy, Suspense, useEffect, useMemo, useRef, useState, type ChangeEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { filesKey, useFolderFiles } from '@kutup/drive-core/files'
import { canShareFile, useSharedFiles } from '@kutup/drive-core/fileShares'
import { FileShareDialog } from '@kutup/drive-ui/FileShareDialog'
import { LOCATION_LABEL_MAX } from '@kutup/chat-core/types'
import { toGpx, toKml } from '@kutup/map/exchange'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import { useFolders } from '@kutup/drive-core/folders'
import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { useRenameFile, useTrashFile } from '@kutup/drive-core/mutations'
import { rekeyFile } from '@kutup/drive-core/rekey'
import { useEffectiveMap, useMapConfig } from '@kutup/map/config'
import { addPlace, encodeListJson, isListName, LIST_EXTENSION, LIST_MIME, listTitle, removePlace, updatePlace, type Place } from '@kutup/map/list'
import { appUrl } from '@kutup/session/apps'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { KutupLogo } from '@kutup/ui/components/brand'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@kutup/ui/components/dropdown-menu'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { LoadingPanel } from '@kutup/ui/components/states'
import { ThemeToggle } from '@kutup/ui/components/theme-toggle'
import { formatFileDate } from '@kutup/ui/lib/format'
import { PersonName } from '../people/PersonName'
import { asPlaces, IMPORT_ACCEPT, PlaceFileTooLarge, readChosenFile, saveFile, UnreadablePlaceFile } from './files'
import { PlaceDialog, type PlaceDraft } from './PlaceDialog'
import { TitleDialog } from './TitleDialog'
import { useListSession } from './useListSession'

const MapView = lazy(() => import('@kutup/map/MapView').then((m) => ({ default: m.MapView })))

const WORLD = { center: { lat: 20, lon: 0 }, zoom: 1.5 }

type Failure = 'notFound' | 'undecryptable' | 'waiting' | 'notAList' | 'loadFailed'

/**
 * `/lists/:cid/:fid` (a list in a folder) and `/shared/:fid` (a list shared
 * by itself): the map, its places, and everyone else in it live.
 */
export function ListPage({ shared = false }: { shared?: boolean }) {
  const { cid = '', fid = '' } = useParams()
  return <OpenList key={`${shared ? 'shared' : cid}/${fid}`} cid={shared ? null : cid} fid={fid} />
}

function OpenList({ cid, fid }: { cid: string | null; fid: string }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const folders = useFolders()
  const inFolder = folders.data?.byId.get(cid ?? '')
  const folderFiles = useFolderFiles(inFolder)
  const sharedFiles = useSharedFiles({ enabled: cid === null })
  const sharedFile = cid === null ? sharedFiles.data?.find((s) => s.file.id === fid) : undefined
  const folder = cid === null ? sharedFile?.container : inFolder
  const file = cid === null ? sharedFile?.file : folderFiles.data?.find((f) => f.id === fid)
  const files = cid === null ? sharedFiles : folderFiles

  // The file as it opened: its key is what the session holds (a rename
  // refetches the list, and fresh key copies must not reopen the session).
  const [picked, setPicked] = useState<{ folder: Folder; file: DriveFile } | null>(null)
  const [failure, setFailure] = useState<Failure | null>(null)

  const listsLoaded = cid === null ? files.isSuccess : folders.isSuccess && (!folder?.key || files.isSuccess)
  const refetching = folders.isFetching || files.isFetching
  useEffect(() => {
    if (picked || failure || !listsLoaded) return
    if (sharedFile?.state === 'waiting') return setFailure('waiting')
    if (folder && file) {
      if ((!folder.key && folder.source !== 'file') || !file.fileKey || !file.name) return setFailure('undecryptable')
      if (!isListName(file.name)) return setFailure('notAList')
      // An editor writes only under the folder's current key.
      if (folder.canUpload && folder.source !== 'file' && file.keyEpoch < folder.keyEpoch) {
        rekeyFile(folder, file).then(
          (rekeyed) => {
            void queryClient.invalidateQueries({ queryKey: filesKey(folder.id) })
            setPicked({ folder, file: rekeyed })
          },
          () => setFailure('loadFailed'),
        )
        return
      }
      setPicked({ folder, file })
    } else if (!refetching) {
      setFailure(folders.isError || files.isError ? 'loadFailed' : 'notFound')
    }
  }, [picked, failure, listsLoaded, refetching, folder, file, sharedFile?.state, folders.isError, files.isError, queryClient])

  if (failure) return <FailurePanel failure={failure} />
  if (!picked) {
    return (
      <div className="flex min-h-svh items-center justify-center bg-background">
        <LoadingPanel label={t('list.opening')} />
      </div>
    )
  }
  return (
    <Workspace
      folder={folder ?? picked.folder}
      file={file ?? picked.file}
      opened={picked.file}
      readOnly={!picked.folder.canUpload}
      editsWait={sharedFile?.state === 'editsWait' && sharedFile.canEdit}
    />
  )
}

function FailurePanel({ failure }: { failure: Failure }) {
  const { t } = useTranslation()
  return (
    <div className="flex min-h-svh items-center justify-center bg-background p-6">
      <div className="max-w-md space-y-4 text-center">
        <h1 className="text-lg font-semibold">{t('list.failedTitle')}</h1>
        <p className="text-sm text-muted-foreground">{t(`list.failure.${failure}`)}</p>
        <Button variant="outline" asChild>
          <Link to="/">
            <ArrowLeft /> {t('list.backToLists')}
          </Link>
        </Button>
      </div>
    </div>
  )
}

type Dialog =
  /** Adding a place (no `placeId`) or changing one; `draft` is what the form starts from. */
  | { kind: 'place'; draft: PlaceDraft; placeId?: string }
  | { kind: 'rename' }
  | { kind: 'trash' }
  | { kind: 'share' }
  | null

function Workspace({
  folder,
  file,
  opened,
  readOnly,
  editsWait,
}: {
  folder: Folder
  /** The file as listed now (its name follows renames). */
  file: DriveFile
  /** The file as it opened, whose key the session uses. */
  opened: DriveFile
  readOnly: boolean
  editsWait: boolean
}) {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const session = useRequiredSession()
  const list = useListSession(opened, readOnly)
  const identity = useDriveIdentity()
  const effectiveMap = useEffectiveMap()
  const mapConfig = useMapConfig()
  const rename = useRenameFile()
  const trash = useTrashFile()
  const [selected, setSelected] = useState<string | null>(null)
  const [picking, setPicking] = useState(false)
  const [dialog, setDialog] = useState<Dialog>(null)
  const [view, setView] = useState<{ center: { lat: number; lon: number }; zoom: number }>(WORLD)
  const importInput = useRef<HTMLInputElement>(null)

  const title = listTitle(file.name ?? '')
  const mayRename = folder.source !== 'file' && (folder.canManage || (folder.canDelete && file.uploaderUserId === session.userId))
  const mayTrash = mayRename
  const editable = !readOnly && list.doc !== null && list.status !== 'error' && identity.isSuccess
  // Who added a place, as `user@server`.
  const me = identity.data?.account ?? ''

  useEffect(() => {
    const previous = document.title
    document.title = `${title} · ${t('app.title')}`
    return () => {
      document.title = previous
    }
  }, [title, t])

  // A place removed by someone else is no longer selected.
  useEffect(() => {
    if (selected && !list.places.some((p) => p.id === selected)) setSelected(null)
  }, [list.places, selected])

  const markers = useMemo(() => list.places.map((p) => ({ id: p.id, lat: p.lat, lon: p.lon, label: p.name })), [list.places])

  function select(place: Place) {
    setSelected(place.id)
    setView({ center: { lat: place.lat, lon: place.lon }, zoom: Math.max(view.zoom, 14) })
  }

  function download() {
    saveFile(file.name ?? `list.${LIST_EXTENSION}`, encodeListJson(list.places).slice(), LIST_MIME)
  }

  /** Add the places in a KML, GPX or Kutup list file, read on this device. */
  async function importPlaces(event: ChangeEvent<HTMLInputElement>) {
    const chosen = event.target.files?.[0]
    event.target.value = ''
    if (!chosen || !list.doc) return
    try {
      const imported = await readChosenFile(chosen, (n) => t('list.importPlaceName', { n }))
      if (imported.places.length === 0) return void toast.error(t('list.importEmpty'))
      const doc = list.doc
      let added = 0
      doc.transact(() => {
        for (const place of asPlaces(imported, me)) {
          try {
            addPlace(doc, place)
            added += 1
          } catch {
            break
          }
        }
      })
      const skipped = imported.skipped + imported.places.length - added
      toast.success(skipped > 0 ? t('list.importedSkipped', { count: added, skipped }) : t('list.imported', { count: added }))
    } catch (error) {
      toast.error(
        error instanceof UnreadablePlaceFile
          ? t('list.importUnreadable')
          : error instanceof PlaceFileTooLarge
            ? t('list.importTooLarge')
            : t('list.importFailed'),
      )
    }
  }

  /** Send a place into a chat: Chat asks which ones; the place travels in the link's fragment only. */
  function sendToChat(place: Place) {
    const label = [...place.name].slice(0, LOCATION_LABEL_MAX).join('')
    const fragment = new URLSearchParams({ lat: String(place.lat), lon: String(place.lon), label })
    window.open(appUrl('chat', `/share-place#${fragment.toString()}`), '_blank', 'noopener')
  }

  const statusText =
    list.status === 'error'
      ? t('list.status.error')
      : list.status === 'connecting'
        ? t('list.status.connecting')
        : readOnly
          ? editsWait
            ? t('list.status.editsWait')
            : t('list.status.viewOnly')
          : t('list.status.live')

  return (
    <div className="flex h-svh flex-col overflow-hidden bg-background">
      <header className="flex h-12 shrink-0 items-center gap-2 border-b border-border bg-background/95 px-2 sm:px-3">
        <Button variant="ghost" size="icon" asChild>
          <Link to="/" aria-label={t('list.backToLists')}>
            <ArrowLeft />
          </Link>
        </Button>
        <KutupLogo size={22} className="hidden shrink-0 sm:block" />
        {mayRename ? (
          <button
            type="button"
            onClick={() => setDialog({ kind: 'rename' })}
            title={t('list.rename')}
            className="min-w-0 truncate rounded px-1.5 py-1 text-sm font-medium hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            {title}
          </button>
        ) : (
          <span className="min-w-0 truncate px-1.5 text-sm font-medium">{title}</span>
        )}
        <div className="ml-auto flex shrink-0 items-center gap-1.5">
          <span
            className="inline-flex items-center gap-1.5 rounded-full bg-muted px-2.5 py-1 text-xs font-medium text-muted-foreground"
            data-testid="list-status"
          >
            {readOnly ? <Eye className="size-3.5" aria-hidden /> : null}
            {statusText}
          </span>
          {list.collaborators > 0 ? (
            <span className="inline-flex items-center gap-1 text-xs text-muted-foreground" title={t('list.collaborators', { count: list.collaborators })}>
              <Users className="size-4" aria-hidden />
              <span aria-hidden>{list.collaborators}</span>
              <span className="sr-only">{t('list.collaborators', { count: list.collaborators })}</span>
            </span>
          ) : null}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" aria-label={t('list.menu')}>
                <MoreHorizontal />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              {canShareFile(folder, file) ? (
                <DropdownMenuItem onSelect={() => setDialog({ kind: 'share' })}>
                  <UserPlus /> {t('list.share')}
                </DropdownMenuItem>
              ) : null}
              {mayRename ? (
                <DropdownMenuItem onSelect={() => setDialog({ kind: 'rename' })}>
                  <Pencil /> {t('list.rename')}
                </DropdownMenuItem>
              ) : null}
              {editable ? (
                <DropdownMenuItem onSelect={() => importInput.current?.click()}>
                  <Upload /> {t('list.import')}
                </DropdownMenuItem>
              ) : null}
              <DropdownMenuSeparator />
              <DropdownMenuItem onSelect={() => saveFile(`${title}.kml`, toKml(title, list.places), 'application/vnd.google-earth.kml+xml')} disabled={list.status === 'connecting'}>
                <FileDown /> {t('list.exportKml')}
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => saveFile(`${title}.gpx`, toGpx(title, list.places), 'application/gpx+xml')} disabled={list.status === 'connecting'}>
                <FileDown /> {t('list.exportGpx')}
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={download} disabled={list.status === 'connecting'}>
                <Download /> {t('list.download')}
              </DropdownMenuItem>
              {mayTrash ? (
                <>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem destructive onSelect={() => setDialog({ kind: 'trash' })}>
                    <Trash2 /> {t('list.trash')}
                  </DropdownMenuItem>
                </>
              ) : null}
            </DropdownMenuContent>
          </DropdownMenu>
          <div className="hidden sm:block">
            <ThemeToggle onChrome={false} />
          </div>
        </div>
      </header>

      <div className="flex min-h-0 flex-1 flex-col-reverse md:flex-row">
        <aside className="flex min-h-0 flex-1 flex-col border-t border-border md:w-80 md:flex-none md:border-r md:border-t-0">
          {editable ? (
            <div className="space-y-2 border-b border-border p-3">
              {picking ? (
                <div className="flex items-center gap-2">
                  <p className="min-w-0 flex-1 text-sm text-muted-foreground">{t('list.pickHint')}</p>
                  <Button variant="ghost" size="icon" onClick={() => setPicking(false)} aria-label={t('common.cancel')}>
                    <X />
                  </Button>
                </div>
              ) : (
                <div className="flex gap-2">
                  {effectiveMap ? (
                    <Button className="flex-1" onClick={() => setPicking(true)}>
                      <MapPin /> {t('list.addOnMap')}
                    </Button>
                  ) : null}
                  <Button
                    variant={effectiveMap ? 'outline' : 'default'}
                    className={effectiveMap ? '' : 'flex-1'}
                    onClick={() => setDialog({ kind: 'place', draft: EMPTY_DRAFT })}
                    title={t('list.addByDetails')}
                  >
                    <Plus /> {effectiveMap ? <span className="sr-only">{t('list.addByDetails')}</span> : t('list.addByDetails')}
                  </Button>
                </div>
              )}
            </div>
          ) : null}
          {editsWait ? <Alert className="m-3">{t('list.editsWaitHint')}</Alert> : null}
          <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain">
            {list.status === 'connecting' && list.places.length === 0 ? (
              <LoadingPanel label={t('list.loadingPlaces')} />
            ) : list.places.length === 0 ? (
              <p className="p-6 text-center text-sm text-muted-foreground">{editable ? t('list.emptyEditor') : t('list.empty')}</p>
            ) : (
              <ul className="divide-y divide-border" aria-label={t('list.placesLabel')}>
                {list.places.map((place) => {
                  const active = place.id === selected
                  return (
                    <li key={place.id} className={active ? 'bg-accent' : undefined}>
                      <div className="flex items-start gap-2 px-3 py-2">
                        <button
                          type="button"
                          onClick={() => select(place)}
                          className="min-w-0 flex-1 rounded text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                          aria-pressed={active}
                        >
                          <span className="flex items-center gap-2">
                            <MapPin className={`size-4 shrink-0 ${active ? 'text-primary' : 'text-muted-foreground'}`} aria-hidden />
                            <span className="truncate text-sm font-medium">{place.name}</span>
                          </span>
                          {place.note ? (
                            <span className={`mt-0.5 block whitespace-pre-wrap break-words pl-6 text-xs text-muted-foreground ${active ? '' : 'line-clamp-2'}`}>
                              {place.note}
                            </span>
                          ) : null}
                          {active ? (
                            <span className="mt-1 block space-y-0.5 pl-6 text-xs text-muted-foreground">
                              <span className="block font-mono">
                                {place.lat.toFixed(5)}, {place.lon.toFixed(5)}
                              </span>
                              {place.addedBy ? (
                                <span className="block">
                                  <PersonName
                                    account={place.addedBy}
                                    avatar={false}
                                    format={(name) => t('list.addedBy', { name, date: formatFileDate(place.addedAt, i18n.language) })}
                                  />
                                </span>
                              ) : null}
                            </span>
                          ) : null}
                        </button>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon" className="size-8" aria-label={t('list.placeActions', { name: place.name })}>
                              <MoreHorizontal />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onSelect={() => sendToChat(place)}>
                              <MessageSquare /> {t('list.sendToChat')}
                            </DropdownMenuItem>
                            {editable ? (
                              <>
                                <DropdownMenuItem onSelect={() => setDialog({ kind: 'place', placeId: place.id, draft: { name: place.name, note: place.note, lat: place.lat, lon: place.lon } })}>
                                  <Pencil /> {t('list.editPlace')}
                                </DropdownMenuItem>
                                <DropdownMenuItem
                                  destructive
                                  onSelect={() => {
                                    if (list.doc) removePlace(list.doc, place.id)
                                    toast.success(t('list.removed', { name: place.name }))
                                  }}
                                >
                                  <Trash2 /> {t('list.removePlace')}
                                </DropdownMenuItem>
                              </>
                            ) : null}
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </div>
                    </li>
                  )
                })}
              </ul>
            )}
          </div>
        </aside>

        <section className="relative h-[45svh] shrink-0 md:h-auto md:flex-1" aria-label={t('list.mapRegion')}>
          {effectiveMap ? (
            <Suspense fallback={<Skeleton className="h-full w-full rounded-none" />}>
              <MapView
                center={view.center}
                zoom={view.zoom}
                markers={markers}
                selectedId={selected}
                onMarkerClick={(id) => {
                  const place = list.places.find((p) => p.id === id)
                  if (place) select(place)
                }}
                fitMarkers
                onPick={(point) => {
                  if (!picking) return
                  setPicking(false)
                  setDialog({ kind: 'place', draft: { name: '', note: '', lat: point.lat, lon: point.lon } })
                }}
                className={`h-full w-full ${picking ? '[&_canvas]:cursor-crosshair' : ''}`}
                ariaLabel={t('list.mapLabel', { title })}
              />
            </Suspense>
          ) : mapConfig.data ? (
            <div className="flex h-full items-center justify-center p-6">
              <Alert className="max-w-sm">
                {t('list.mapsOff')}{' '}
                {mapConfig.data.enabled ? (
                  <a href={appUrl('account', '/settings/maps')} className="underline">
                    {t('list.turnOn')}
                  </a>
                ) : null}
              </Alert>
            </div>
          ) : null}
        </section>
      </div>

      <PlaceDialog
        open={dialog?.kind === 'place'}
        mode={dialog?.kind === 'place' && dialog.placeId ? 'edit' : 'add'}
        initial={dialog?.kind === 'place' ? dialog.draft : EMPTY_DRAFT}
        onClose={() => setDialog(null)}
        onSubmit={(values) => {
          if (!list.doc) return
          if (dialog?.kind === 'place' && dialog.placeId) {
            updatePlace(list.doc, dialog.placeId, values)
          } else {
            const place: Place = { id: crypto.randomUUID(), ...values, addedBy: me, addedAt: new Date().toISOString() }
            try {
              addPlace(list.doc, place)
            } catch {
              toast.error(t('list.tooMany'))
              return
            }
            setSelected(place.id)
            setView({ center: { lat: place.lat, lon: place.lon }, zoom: Math.max(view.zoom, 12) })
          }
          setDialog(null)
        }}
      />
      <TitleDialog
        open={dialog?.kind === 'rename'}
        title={t('list.renameTitle')}
        initial={title}
        submit={t('list.renameSubmit')}
        pending={rename.isPending}
        error={rename.error}
        onClose={() => (setDialog(null), rename.reset())}
        onSubmit={(next) =>
          rename.mutate({ folder, file, name: `${next}.${LIST_EXTENSION}` }, { onSuccess: () => setDialog(null) })
        }
      />
      <FileShareDialog target={dialog?.kind === 'share' ? { folder, file } : null} onClose={() => setDialog(null)} />
      <input ref={importInput} type="file" accept={IMPORT_ACCEPT} className="hidden" onChange={(e) => void importPlaces(e)} data-testid="import-places" />
      <ConfirmDestructive
        open={dialog?.kind === 'trash'}
        onOpenChange={(o) => !o && (setDialog(null), trash.reset())}
        title={t('list.trashTitle', { title })}
        description={t('list.trashDescription')}
        submit={t('list.trash')}
        pending={trash.isPending}
        error={trash.error}
        errorFallback={t('list.trashFailed')}
        onConfirm={() =>
          trash.mutate(
            { folder, file },
            {
              onSuccess: () => {
                toast.success(t('list.trashed', { title }))
                void navigate('/')
              },
            },
          )
        }
      />
    </div>
  )
}

const EMPTY_DRAFT: PlaceDraft = { name: '', note: '', lat: null, lon: null }
