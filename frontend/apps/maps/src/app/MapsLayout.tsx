import { ChevronDown, ChevronUp, FileType, HardDrive, Images, Map as MapIcon, MapPinPlus, MessagesSquare, UserRound } from 'lucide-react'
import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Outlet } from 'react-router-dom'
import { usePeople } from '@kutup/drive-core/people'
import { useEffectiveMap, useMapConfig } from '@kutup/map/config'
import type { MapFocus } from '@kutup/map/MapView'
import { appUrl } from '@kutup/session/apps'
import { signOut } from '@kutup/session/signOut'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { AppSwitcher } from '@kutup/ui/components/app-switcher'
import { Button } from '@kutup/ui/components/button'
import { BrandLockup } from '@kutup/ui/components/brand'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { UserMenu } from '@kutup/ui/components/user-menu'
import { cn } from '@kutup/ui/lib/cn'
import { useAddToLists, useWritableLists } from '../features/lists/addPlace'
import { useAtlas } from '../features/lists/atlasContext'
import { PlaceCard } from '../features/lists/PlaceCard'
import { PlaceDialog, type PlaceDraft } from '../features/lists/PlaceDialog'
import { StageContext, type Scene, type SceneHandlers, type Stage } from './stage'

const MapView = lazy(() => import('@kutup/map/MapView').then((m) => ({ default: m.MapView })))

const WORLD = { lat: 25, lon: 10 }
const EMPTY: Scene = { markers: [], selectedId: null, fitKey: null, picking: false, label: '' }
const EMPTY_DRAFT: PlaceDraft = { name: '', note: '', lat: null, lon: null }

/**
 * The Maps app: one map that stays in place, and a panel beside it (a sheet
 * over it on a phone) that shows your maps or one list. The address follows
 * the panel, so links, reloads and Back work as on any page.
 */
export function MapsLayout() {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const effective = useEffectiveMap()
  const config = useMapConfig()
  // Names and pictures of the people lists are shared with.
  usePeople()
  const [scene, setScene] = useState<Scene>(EMPTY)
  const handlers = useRef<SceneHandlers>({})
  const [focus, setFocus] = useState<MapFocus | null>(null)
  const seq = useRef(0)
  const [expanded, setExpanded] = useState(false)
  const atlas = useAtlas()
  const writable = useWritableLists()
  const addToLists = useAddToLists()
  // Right-click on the map: a small menu there, then the place dialog.
  const [menu, setMenu] = useState<{ lat: number; lon: number; x: number; y: number } | null>(null)
  const [draft, setDraft] = useState<PlaceDraft | null>(null)
  const [adding, setAdding] = useState(false)
  useEffect(() => {
    if (!menu) return
    const close = (event: KeyboardEvent) => event.key === 'Escape' && setMenu(null)
    window.addEventListener('keydown', close)
    return () => window.removeEventListener('keydown', close)
  }, [menu])
  const openList = atlas.open?.fileId
  const mapArea = useRef<HTMLElement>(null)
  // The menu opens at the click, kept inside the map (its size, with a margin).
  const menuPosition = (x: number, y: number) => {
    const width = mapArea.current?.clientWidth ?? Infinity
    const height = mapArea.current?.clientHeight ?? Infinity
    return { left: Math.max(8, Math.min(x, width - 232)), top: Math.max(8, Math.min(y, height - 100)) }
  }

  const stage = useMemo<Stage>(
    () => ({
      show: (next, nextHandlers) => {
        handlers.current = nextHandlers
        setScene(next)
      },
      focus: (point, zoom) => setFocus({ ...point, zoom, seq: ++seq.current }),
    }),
    [],
  )

  return (
    <StageContext.Provider value={stage}>
      <div className="relative h-svh overflow-hidden bg-background md:flex">
        <main ref={mapArea} className="absolute inset-0 md:relative md:inset-auto md:order-2 md:min-w-0 md:flex-1" aria-label={t('layout.map')}>
          {effective ? (
            <Suspense fallback={<Skeleton className="h-full w-full rounded-none" />}>
              <MapView
                center={WORLD}
                zoom={1.5}
                markers={scene.markers}
                selectedId={scene.selectedId}
                fitKey={scene.fitKey}
                focus={focus}
                onMarkerClick={(id) => {
                  setMenu(null)
                  handlers.current.onMarkerClick?.(id)
                }}
                onPick={(point) => {
                  setMenu(null)
                  if (scene.picking) handlers.current.onPick?.(point)
                }}
                onContextMenu={(point) => setMenu(point)}
                className={cn('h-full w-full', scene.picking && '[&_canvas]:cursor-crosshair')}
                ariaLabel={scene.label || t('layout.map')}
              />
            </Suspense>
          ) : config.data ? (
            <div className="flex h-full items-start justify-center p-6 md:items-center">
              <Alert className="max-w-sm">
                {t('layout.mapsOff')}{' '}
                {config.data.enabled ? (
                  <a href={appUrl('account', '/settings/maps')} className="underline">
                    {t('layout.turnOn')}
                  </a>
                ) : null}
              </Alert>
            </div>
          ) : null}
          {menu ? (
            <div
              className="absolute z-30 w-56 rounded-lg border border-border bg-popover p-1 text-popover-foreground shadow-lg"
              style={menuPosition(menu.x, menu.y)}
              role="menu"
              aria-label={t('layout.mapMenu')}
            >
              <p className="px-2 py-1 font-mono text-xs text-muted-foreground">
                {menu.lat.toFixed(5)}, {menu.lon.toFixed(5)}
              </p>
              <Button
                variant="ghost"
                size="sm"
                role="menuitem"
                className="w-full justify-start"
                autoFocus
                onClick={() => {
                  setDraft({ name: '', note: '', lat: menu.lat, lon: menu.lon })
                  setMenu(null)
                }}
              >
                <MapPinPlus /> {t('layout.addHere')}
              </Button>
            </div>
          ) : null}
          <PlaceCard />
        </main>

        <aside
          className={cn(
            'absolute inset-x-0 bottom-0 z-10 flex flex-col rounded-t-2xl border-t border-border bg-background shadow-2xl',
            expanded ? 'h-[88svh]' : 'h-[45svh]',
            'md:static md:order-1 md:h-full md:w-96 md:shrink-0 md:rounded-none md:border-r md:border-t-0 md:shadow-none',
          )}
        >
          <button
            type="button"
            className="flex h-6 shrink-0 items-center justify-center text-muted-foreground md:hidden"
            onClick={() => setExpanded((v) => !v)}
            aria-label={expanded ? t('layout.collapse') : t('layout.expand')}
            aria-expanded={expanded}
          >
            {expanded ? <ChevronDown className="size-4" /> : <ChevronUp className="size-4" />}
          </button>
          <header className="flex h-12 shrink-0 items-center gap-2 px-4 md:h-14">
            <BrandLockup app={t('apps.maps')} className="min-w-0 flex-1" />
            <AppSwitcher
              currentId="maps"
              apps={[
                { id: 'drive', name: t('apps.drive'), href: appUrl('drive'), icon: <HardDrive /> },
                { id: 'office', name: t('apps.office'), href: appUrl('office'), icon: <FileType /> },
                { id: 'chat', name: t('apps.chat'), href: appUrl('chat'), icon: <MessagesSquare /> },
                { id: 'photos', name: t('apps.photos'), href: appUrl('photos'), icon: <Images /> },
                { id: 'maps', name: t('apps.maps'), href: appUrl('maps'), icon: <MapIcon /> },
                { id: 'account', name: t('apps.account'), href: appUrl('account'), icon: <UserRound /> },
              ]}
            />
            <UserMenu
              name={session.username ?? session.email}
              email={session.email}
              settingsHref={appUrl('account', '/settings/profile')}
              onSignOut={() => {
                void signOut().then(() => window.location.assign(appUrl('account', '/login')))
              }}
            />
          </header>
          <div className="flex min-h-0 flex-1 flex-col border-t border-border">
            <Outlet />
          </div>
        </aside>
      </div>
      <PlaceDialog
        open={draft !== null}
        mode="add"
        initial={draft ?? EMPTY_DRAFT}
        lists={writable}
        // In a list: that one to start with; choose others as well, or instead.
        initialLists={openList && writable.some((l) => l.id === openList) ? [openList] : []}
        busy={adding}
        onClose={() => setDraft(null)}
        onSubmit={(values, lists, newList) => {
          setAdding(true)
          void addToLists(values, lists, newList)
            .then((added) => {
              if (!added) return
              setDraft(null)
              if (added.fileId) atlas.showPlace({ place: added.place, fileId: added.fileId })
            })
            .finally(() => setAdding(false))
        }}
      />
    </StageContext.Provider>
  )
}
