import { useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Download, Eye, FileDown, MapPin, MessageSquare, MoreHorizontal, Pencil, Plus, Trash2, Upload, UserPlus, Users, X } from 'lucide-react'
import { useEffect, useMemo, useRef, useState, type ChangeEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { filesKey, useFolderFiles } from '@kutup/drive-core/files'
import { shareRole, useSharedFiles } from '@kutup/drive-core/fileShares'
import { useFolders } from '@kutup/drive-core/folders'
import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { useRenameFile, useTrashFile } from '@kutup/drive-core/mutations'
import { rekeyFile } from '@kutup/drive-core/rekey'
import { FileShareDialog } from '@kutup/drive-ui/FileShareDialog'
import { useEffectiveMap } from '@kutup/map/config'
import { toGpx, toKml } from '@kutup/map/exchange'
import { addPlace, encodeListJson, isListName, LIST_EXTENSION, LIST_MIME, listTitle, removePlace, updatePlace, type Place } from '@kutup/map/list'
import { appUrl } from '@kutup/session/apps'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@kutup/ui/components/dropdown-menu'
import { LoadingPanel } from '@kutup/ui/components/states'
import { cn } from '@kutup/ui/lib/cn'
import { useMapScene, useStage } from '../../app/stage'
import { useAddToLists, useWritableLists } from './addPlace'
import { useAtlas } from './atlasContext'
import { sendToChat } from './chat'
import { asPlaces, IMPORT_ACCEPT, PlaceFileTooLarge, readChosenFile, saveFile, UnreadablePlaceFile } from './files'
import { PlaceDialog, type PlaceDraft } from './PlaceDialog'
import { TitleDialog } from './TitleDialog'
import { useListSession } from './useListSession'

type Failure = 'notFound' | 'undecryptable' | 'waiting' | 'notAList' | 'loadFailed'

/**
 * The panel for one list — `/lists/:cid/:fid` (in a folder) or `/shared/:fid`
 * (shared by itself): its places, edited live with everyone in it, on the
 * map beside it.
 */
export function ListPanel({ shared = false, remote = false }: { shared?: boolean; remote?: boolean }) {
  const { cid = '', fid = '', shareId = '' } = useParams()
  const key = shared ? `shared/${fid}` : remote ? `remote/${shareId}/${fid}` : `${cid}/${fid}`
  return <OpenList key={key} cid={shared ? null : cid} shareId={remote ? shareId : null} fid={fid} />
}

function OpenList({ cid, shareId, fid }: { cid: string | null; shareId: string | null; fid: string }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const folders = useFolders()
  // A folder here, or (`/remote/:shareId/…`) one shared from another server.
  const inFolder = shareId
    ? folders.data?.sharedWithMe.find((f) => f.remoteShareId === shareId)
    : folders.data?.byId.get(cid ?? '')
  const folderFiles = useFolderFiles(inFolder)
  const byItself = cid === null && shareId === null
  const sharedFiles = useSharedFiles({ enabled: byItself })
  const sharedFile = byItself ? sharedFiles.data?.find((s) => s.file.id === fid) : undefined
  const folder = byItself ? sharedFile?.container : inFolder
  const file = byItself ? sharedFile?.file : folderFiles.data?.find((f) => f.id === fid)
  const files = byItself ? sharedFiles : folderFiles

  // The file as it opened: its key is what the session holds (a rename
  // refetches the list, and fresh key copies must not reopen the session).
  const [picked, setPicked] = useState<{ folder: Folder; file: DriveFile } | null>(null)
  const [failure, setFailure] = useState<Failure | null>(null)

  const listsLoaded = byItself ? files.isSuccess : folders.isSuccess && (!folder?.key || files.isSuccess)
  const refetching = folders.isFetching || files.isFetching
  useEffect(() => {
    if (picked || failure || !listsLoaded) return
    if (sharedFile?.state === 'waiting') return setFailure('waiting')
    if (sharedFile?.state === 'gone') return setFailure('notFound')
    if (folder && file) {
      if ((!folder.key && folder.source !== 'file') || !file.fileKey || !file.name) return setFailure('undecryptable')
      if (!isListName(file.name)) return setFailure('notAList')
      // An editor writes only under the folder's current key (in folders
      // here: a file shared by itself or from another server is not re-keyed).
      const localFolder = folder.source === 'owned' || folder.source === 'shared'
      if (localFolder && folder.canUpload && file.keyEpoch < folder.keyEpoch) {
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

  if (failure) {
    return (
      <div className="space-y-4 p-6">
        <BackToMaps />
        <h2 className="font-semibold">{t('list.failedTitle')}</h2>
        <p className="text-sm text-muted-foreground">{t(`list.failure.${failure}`)}</p>
      </div>
    )
  }
  if (!picked) return <LoadingPanel label={t('list.opening')} />
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

/**
 * Where the back button goes: the list's folder in Drive when the list was
 * opened from there (`?from=drive`), otherwise this app's lists. The folder
 * comes from this page's own route, so the parameter cannot send anyone
 * elsewhere.
 */
function useBack(): { drive: string | null; label: string } {
  const { t } = useTranslation()
  const { search } = useLocation()
  const { cid, shareId } = useParams()
  if (new URLSearchParams(search).get('from') !== 'drive') return { drive: null, label: t('list.backToLists') }
  const folder = cid ? `/folders/${cid}` : shareId ? `/remote/${shareId}` : '/shared'
  return { drive: appUrl('drive', folder), label: t('list.backToDrive') }
}

function BackToMaps() {
  const back = useBack()
  return (
    <Button variant="ghost" size="sm" asChild className="-ml-2">
      {back.drive ? (
        <a href={back.drive}>
          <ArrowLeft /> {back.label}
        </a>
      ) : (
        <Link to="/">
          <ArrowLeft /> {back.label}
        </Link>
      )}
    </Button>
  )
}

type Dialog =
  /** Adding a place (no `placeId`) or changing one; `draft` is what the form starts from. */
  | { kind: 'place'; draft: PlaceDraft; placeId?: string }
  | { kind: 'rename' }
  | { kind: 'trash' }
  | { kind: 'share' }
  | null

const EMPTY_DRAFT: PlaceDraft = { name: '', note: '', lat: null, lon: null }

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
  const { t } = useTranslation()
  const back = useBack()
  const navigate = useNavigate()
  const location = useLocation()
  const session = useRequiredSession()
  const stage = useStage()
  const atlas = useAtlas()
  // Here or on another server (through this one): the same live session.
  const effectiveMap = useEffectiveMap()
  // Its saves also redraw its picture in Drive: this map, the list's colour.
  const list = useListSession(opened, readOnly, folder, { map: effectiveMap, color: atlas.colorOf(file.id) })
  const rename = useRenameFile()
  const trash = useTrashFile()
  const writable = useWritableLists()
  const addToLists = useAddToLists()
  const [selected, setSelected] = useState<string | null>(null)
  const [picking, setPicking] = useState(false)
  const [adding, setAdding] = useState(false)
  const [dialog, setDialog] = useState<Dialog>(null)
  const importInput = useRef<HTMLInputElement>(null)

  const title = listTitle(file.name ?? '')
  const role = shareRole(folder, file, atlas.lists.find((l) => l.file.id === file.id)?.shared)
  // Owners and uploaders who may delete; editors of a file shared by itself too.
  const mayRename =
    folder.source === 'file' ? folder.canUpload : folder.canManage || (folder.canDelete && file.uploaderUserId === session.userId)
  const mayTrash = folder.source !== 'file' && mayRename
  const editable = !readOnly && list.doc !== null && list.status !== 'error' && atlas.me !== null
  const color = atlas.colorOf(file.id)
  const { setOpen, showPlace } = atlas

  useEffect(() => {
    const previous = document.title
    document.title = `${title} · ${t('app.title')}`
    return () => {
      document.title = previous
    }
  }, [title, t])

  // The live places, for the place card and adding to several lists.
  useEffect(() => {
    if (list.doc) setOpen({ fileId: file.id, doc: list.doc, places: list.places })
  }, [list.doc, list.places, file.id, setOpen])
  useEffect(() => () => setOpen(null), [setOpen])

  // A place removed by someone else is no longer selected.
  useEffect(() => {
    if (selected && !list.places.some((p) => p.id === selected)) setSelected(null)
  }, [list.places, selected])

  function select(place: Place) {
    setSelected(place.id)
    stage.focus(place, 15)
    showPlace({ place, fileId: file.id })
  }

  // Opened from a pin elsewhere: that place, once the places are in.
  const wanted = useRef((location.state as { place?: string } | null)?.place ?? null)
  useEffect(() => {
    const place = wanted.current ? list.places.find((p) => p.id === wanted.current) : undefined
    if (place) {
      wanted.current = null
      select(place)
    }
    // select is stable enough: it only reads setters and this list.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [list.places])

  const markers = useMemo(() => list.places.map((p) => ({ id: p.id, lat: p.lat, lon: p.lon, label: p.name, color })), [list.places, color])
  useMapScene(
    { markers, selectedId: selected, fitKey: `list:${file.id}`, picking, label: t('list.mapLabel', { title }) },
    {
      onMarkerClick: (id) => {
        const place = list.places.find((p) => p.id === id)
        if (place) select(place)
      },
      onPick: (point) => {
        setPicking(false)
        setDialog({ kind: 'place', draft: { name: '', note: '', lat: point.lat, lon: point.lon } })
      },
    },
  )

  function download() {
    saveFile(file.name ?? `list.${LIST_EXTENSION}`, encodeListJson(list.places).slice(), LIST_MIME)
  }

  /** Add the places in a KML, GPX or Kutup list file, read on this device. */
  async function importPlaces(event: ChangeEvent<HTMLInputElement>) {
    const chosen = event.target.files?.[0]
    event.target.value = ''
    if (!chosen || !list.doc || !atlas.me) return
    try {
      const imported = await readChosenFile(chosen, (n) => t('list.importPlaceName', { n }))
      if (imported.places.length === 0) return void toast.error(t('list.importEmpty'))
      const doc = list.doc
      let added = 0
      doc.transact(() => {
        for (const place of asPlaces(imported, atlas.me!)) {
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

  const editingPlace = dialog?.kind === 'place' ? dialog.placeId : undefined

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex shrink-0 items-center gap-1 px-2 pt-2">
        <Button variant="ghost" size="icon" asChild>
          {back.drive ? (
            <a href={back.drive} aria-label={back.label}>
              <ArrowLeft />
            </a>
          ) : (
            <Link to="/" aria-label={back.label}>
              <ArrowLeft />
            </Link>
          )}
        </Button>
        <span className="size-3 shrink-0 rounded-full" style={{ backgroundColor: color }} aria-hidden />
        {mayRename ? (
          <button
            type="button"
            onClick={() => setDialog({ kind: 'rename' })}
            title={t('list.rename')}
            className="min-w-0 flex-1 truncate rounded px-1.5 py-1 text-left font-display text-lg font-semibold hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            {title}
          </button>
        ) : (
          <h1 className="min-w-0 flex-1 truncate px-1.5 font-display text-lg font-semibold">{title}</h1>
        )}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" aria-label={t('list.menu')}>
              <MoreHorizontal />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            {role ? (
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
      </div>
      <div className="flex shrink-0 items-center gap-2 px-4 pb-2">
        <span className="inline-flex items-center gap-1.5 rounded-full bg-muted px-2.5 py-0.5 text-xs font-medium text-muted-foreground" data-testid="list-status">
          {readOnly ? <Eye className="size-3.5" aria-hidden /> : null}
          {statusText}
        </span>
        <span className="text-xs text-muted-foreground">{t('list.placeCount', { count: list.places.length })}</span>
        {list.collaborators > 0 ? (
          <span className="ml-auto inline-flex items-center gap-1 text-xs text-muted-foreground" title={t('list.collaborators', { count: list.collaborators })}>
            <Users className="size-4" aria-hidden />
            <span aria-hidden>{list.collaborators}</span>
            <span className="sr-only">{t('list.collaborators', { count: list.collaborators })}</span>
          </span>
        ) : null}
      </div>

      {editable ? (
        <div className="shrink-0 px-4 pb-3">
          {picking ? (
            <div className="flex items-center gap-2 rounded-md border border-primary/40 bg-primary/5 px-3 py-2">
              <p className="min-w-0 flex-1 text-sm">{t('list.pickHint')}</p>
              <Button variant="ghost" size="icon" className="size-7" onClick={() => setPicking(false)} aria-label={t('common.cancel')}>
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
          {effectiveMap && !picking ? <p className="mt-1.5 hidden text-xs text-muted-foreground md:block">{t('list.rightClickHint')}</p> : null}
        </div>
      ) : null}
      {editsWait ? (
        <div className="shrink-0 px-4 pb-3">
          <Alert>{t('list.editsWaitHint')}</Alert>
        </div>
      ) : null}

      <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain border-t border-border">
        {list.status === 'connecting' && list.places.length === 0 ? (
          <LoadingPanel label={t('list.loadingPlaces')} />
        ) : list.places.length === 0 ? (
          <p className="p-6 text-center text-sm text-muted-foreground">{editable ? t('list.emptyEditor') : t('list.empty')}</p>
        ) : (
          <ul className="divide-y divide-border" aria-label={t('list.placesLabel')}>
            {list.places.map((place) => {
              const active = place.id === selected
              return (
                <li key={place.id} className={cn(active && 'bg-accent')}>
                  <div className="flex items-start gap-2 px-3 py-2">
                    <button
                      type="button"
                      onClick={() => select(place)}
                      className="min-w-0 flex-1 rounded text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                      aria-pressed={active}
                    >
                      <span className="flex items-center gap-2">
                        <MapPin className={cn('size-4 shrink-0', active ? 'text-primary' : 'text-muted-foreground')} aria-hidden />
                        <span className="truncate text-sm font-medium">{place.name}</span>
                      </span>
                      {place.note ? (
                        <span className={cn('mt-0.5 block whitespace-pre-wrap break-words pl-6 text-xs text-muted-foreground', !active && 'line-clamp-2')}>{place.note}</span>
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
                            <DropdownMenuItem
                              onSelect={() =>
                                setDialog({ kind: 'place', placeId: place.id, draft: { name: place.name, note: place.note, lat: place.lat, lon: place.lon } })
                              }
                            >
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

      <PlaceDialog
        open={dialog?.kind === 'place'}
        mode={editingPlace ? 'edit' : 'add'}
        initial={dialog?.kind === 'place' ? dialog.draft : EMPTY_DRAFT}
        // Adding: this list, and any others as in Google Maps' "Save to".
        lists={editingPlace ? undefined : writable}
        initialLists={[file.id]}
        busy={adding}
        onClose={() => setDialog(null)}
        onSubmit={(values, lists, newList) => {
          if (!list.doc) return
          if (editingPlace) {
            updatePlace(list.doc, editingPlace, values)
            setDialog(null)
            return
          }
          setAdding(true)
          void addToLists(values, lists, newList)
            .then((added) => {
              if (!added) return
              const { place } = added
              setDialog(null)
              if (lists.includes(file.id)) {
                setSelected(place.id)
                stage.focus(place, 14)
              }
              showPlace({ place, fileId: file.id })
            })
            .finally(() => setAdding(false))
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
        onSubmit={(next) => rename.mutate({ folder, file, name: `${next}.${LIST_EXTENSION}` }, { onSuccess: () => setDialog(null) })}
      />
      <FileShareDialog target={dialog?.kind === 'share' && role ? { folder, file, role } : null} onClose={() => setDialog(null)} />
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
                showPlace(null)
                void navigate('/')
              },
            },
          )
        }
      />
    </div>
  )
}
