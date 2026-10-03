import { Loader2, LocateFixed, MapPin, Radio, Search } from 'lucide-react'
import { lazy, Suspense, useEffect, useMemo, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { LOCATION_LABEL_MAX, type ChatLocationV1 } from '@kutup/chat-core/types'
import { CITIES_ATTRIBUTION, loadCities, searchCities, type City } from '@kutup/map/cities'
import { useEffectiveMap, useMapConfig } from '@kutup/map/config'
import { appUrl } from '@kutup/session/apps'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { LiveShareError } from './liveShares'
import { formatCoordinates } from './places'

const MapView = lazy(() => import('@kutup/map/MapView').then((m) => ({ default: m.MapView })))

type Point = { lat: number; lon: number }

/** How long a live location can be shared, as in WhatsApp. */
const LIVE_DURATIONS = [
  { ms: 15 * 60_000, label: 'chat.liveLocation.for15m' },
  { ms: 60 * 60_000, label: 'chat.liveLocation.for1h' },
  { ms: 8 * 60 * 60_000, label: 'chat.liveLocation.for8h' },
] as const

/** The whole world, before a place is chosen. */
const WORLD = { center: { lat: 30, lon: 15 }, zoom: 1.2 }

/**
 * Send a place once (docs/plans/maps.md): tap the map (when maps are on),
 * use this device's location, or jump to a city found on the device; name it
 * if you like. The place travels end-to-end encrypted.
 */
export function NewLocationDialog({
  open,
  onOpenChange,
  send,
  startLive,
  sharingLive,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  send: (location: ChatLocationV1) => Promise<void>
  /** Share this device's live location for a while (absent in Note to Self). */
  startLive?: (durationMs: number) => Promise<void>
  /** This tab is already sharing its live location here. */
  sharingLive?: boolean
}) {
  const { t } = useTranslation()
  const config = useMapConfig()
  const map = useEffectiveMap()
  const [point, setPoint] = useState<Point | null>(null)
  const [view, setView] = useState(WORLD)
  const [label, setLabel] = useState('')
  const [query, setQuery] = useState('')
  const [cities, setCities] = useState<Awaited<ReturnType<typeof loadCities>> | null>(null)
  const [citiesFailed, setCitiesFailed] = useState(false)
  const [locating, setLocating] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [startingLive, setStartingLive] = useState<number | null>(null)

  useEffect(() => {
    if (!open) return
    setPoint(null)
    setView(WORLD)
    setLabel('')
    setQuery('')
    setError(null)
  }, [open])

  // The city list is only downloaded once someone searches.
  useEffect(() => {
    if (!open || query.trim().length < 2 || cities || citiesFailed) return
    loadCities().then(setCities, () => setCitiesFailed(true))
  }, [open, query, cities, citiesFailed])
  const results = useMemo(() => (cities ? searchCities(cities, query) : []), [cities, query])

  function choose(next: Point, zoom: number) {
    setPoint(next)
    setView({ center: next, zoom })
    setError(null)
  }

  function locate() {
    if (!('geolocation' in navigator)) {
      setError(t('chat.location.unavailable'))
      return
    }
    setLocating(true)
    navigator.geolocation.getCurrentPosition(
      (position) => {
        setLocating(false)
        choose({ lat: position.coords.latitude, lon: position.coords.longitude }, 16)
      },
      (failure) => {
        setLocating(false)
        setError(failure.code === failure.PERMISSION_DENIED ? t('chat.location.denied') : t('chat.location.unavailable'))
      },
      { enableHighAccuracy: true, timeout: 15_000, maximumAge: 60_000 },
    )
  }

  function pickCity(city: City) {
    choose({ lat: city.lat, lon: city.lon }, 11)
    setQuery('')
    if (!label.trim()) setLabel(city.name)
  }

  async function shareLive(durationMs: number) {
    if (!startLive || startingLive !== null) return
    setStartingLive(durationMs)
    setError(null)
    try {
      await startLive(durationMs)
      onOpenChange(false)
    } catch (failure) {
      setError(
        failure instanceof LiveShareError
          ? failure.reason === 'denied'
            ? t('chat.location.denied')
            : t('chat.location.unavailable')
          : t('chat.liveLocation.startFailed'),
      )
    } finally {
      setStartingLive(null)
    }
  }

  const trimmed = label.trim()
  const labelTooLong = [...trimmed].length > LOCATION_LABEL_MAX

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!point || busy || labelTooLong) return
    setBusy(true)
    try {
      await send({ ...point, ...(trimmed ? { label: trimmed } : {}) })
      onOpenChange(false)
    } catch {
      // Said already.
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !busy && onOpenChange(next)}>
      <DialogContent className="max-w-lg" data-testid="chat-new-location">
        <form onSubmit={(event) => void submit(event)} className="space-y-4">
          <DialogHeader>
            <DialogTitle>{t('chat.location.title')}</DialogTitle>
            <DialogDescription>{t('chat.location.description')}</DialogDescription>
          </DialogHeader>

          {startLive ? (
            <section className="space-y-2 rounded-lg border border-border p-3" data-testid="chat-live-location-start">
              <p className="flex items-center gap-2 text-sm font-medium">
                <Radio className="size-4 text-primary" aria-hidden />
                {t('chat.liveLocation.share')}
              </p>
              {sharingLive ? (
                <p className="text-sm text-muted-foreground">{t('chat.liveLocation.alreadySharing')}</p>
              ) : (
                <>
                  <div className="flex flex-wrap gap-2">
                    {LIVE_DURATIONS.map((duration) => (
                      <Button
                        key={duration.ms}
                        type="button"
                        variant="outline"
                        size="sm"
                        disabled={startingLive !== null || busy}
                        onClick={() => void shareLive(duration.ms)}
                        data-testid={`chat-live-location-${duration.ms}`}
                      >
                        {startingLive === duration.ms ? <Loader2 className="animate-spin" /> : null}
                        {t(duration.label)}
                      </Button>
                    ))}
                  </div>
                  <p className="text-xs text-muted-foreground">{t('chat.liveLocation.tabHint')}</p>
                </>
              )}
            </section>
          ) : null}

          {map ? (
            <div className="space-y-1">
              <Suspense fallback={<Skeleton className="h-64 w-full" />}>
                <MapView
                  center={view.center}
                  zoom={view.zoom}
                  markers={point ? [point] : []}
                  onPick={(picked) => {
                    setPoint(picked)
                    setError(null)
                  }}
                  className="h-64 w-full overflow-hidden rounded-lg border border-border"
                  ariaLabel={t('chat.location.mapLabel')}
                />
              </Suspense>
              <p className="text-xs text-muted-foreground">{t('chat.location.pickHint')}</p>
            </div>
          ) : config.data ? (
            <Alert>
              {t('chat.location.mapsOff')}{' '}
              {config.data.enabled ? (
                <a href={appUrl('account', '/settings/maps')} className="underline" data-testid="chat-location-maps-settings">
                  {t('chat.location.turnOn')}
                </a>
              ) : null}
            </Alert>
          ) : null}

          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" onClick={locate} disabled={locating || busy} data-testid="chat-location-current">
              {locating ? <Loader2 className="animate-spin" /> : <LocateFixed />}
              {locating ? t('chat.location.locating') : t('chat.location.useCurrent')}
            </Button>
          </div>

          <div className="space-y-2">
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={t('chat.location.searchCity')}
                aria-label={t('chat.location.searchCity')}
                className="pl-9"
                data-testid="chat-location-city"
              />
            </div>
            {query.trim().length >= 2 ? (
              citiesFailed ? (
                <p className="text-sm text-destructive">{t('chat.location.citiesFailed')}</p>
              ) : !cities ? (
                <p className="text-sm text-muted-foreground">{t('common.loading')}</p>
              ) : results.length === 0 ? (
                <p className="text-sm text-muted-foreground">{t('chat.location.noCities')}</p>
              ) : (
                <ul className="max-h-48 overflow-y-auto rounded-md border border-border" data-testid="chat-location-city-results">
                  {results.map((city) => (
                    <li key={`${city.name}:${city.lat}:${city.lon}`}>
                      <button
                        type="button"
                        className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-accent"
                        onClick={() => pickCity(city)}
                      >
                        <MapPin className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                        <span className="min-w-0 flex-1 truncate">{city.name}</span>
                        <span className="text-xs text-muted-foreground">{city.country}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              )
            ) : null}
            <p className="text-xs text-muted-foreground">{t('chat.location.citiesAttribution', { source: CITIES_ATTRIBUTION })}</p>
          </div>

          {point ? (
            <p className="flex items-center gap-2 text-sm" data-testid="chat-location-chosen">
              <MapPin className="size-4 text-primary" aria-hidden />
              <span className="font-mono">{formatCoordinates(point)}</span>
            </p>
          ) : null}

          <Field
            label={t('chat.location.label')}
            error={labelTooLong ? t('chat.location.labelTooLong', { max: LOCATION_LABEL_MAX }) : undefined}
          >
            {(field) => (
              <Input
                {...field}
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder={t('chat.location.labelPlaceholder')}
                data-testid="chat-location-label-input"
              />
            )}
          </Field>

          {error ? <Alert variant="error">{error}</Alert> : null}

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={!point || busy || labelTooLong} data-testid="chat-location-send">
              {busy ? <Loader2 className="animate-spin" /> : null}
              {t('chat.location.send')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
