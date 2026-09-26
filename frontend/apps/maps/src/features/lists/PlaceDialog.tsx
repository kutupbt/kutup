import { MapPin, Search } from 'lucide-react'
import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { CITIES_ATTRIBUTION, loadCities, searchCities, type City } from '@kutup/map/cities'
import { MAX_NAME, MAX_NOTE } from '@kutup/map/list'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Label } from '@kutup/ui/components/label'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Textarea } from '@kutup/ui/components/textarea'

/** A list a new place can go into. */
export interface ListOption {
  id: string
  title: string
  color: string
}

export interface PlaceDraft {
  name: string
  note: string
  lat: number | null
  lon: number | null
}

/**
 * Add a place or change one: its name, a note, and where it is — from a
 * click on the map, a city found on this device, or typed coordinates.
 */
export function PlaceDialog({
  open,
  mode,
  initial,
  lists,
  initialLists = [],
  busy = false,
  onClose,
  onSubmit,
}: {
  open: boolean
  mode: 'add' | 'edit'
  initial: PlaceDraft
  /** Adding: the lists it can go into, to choose one or more (as Google Maps' "Save to"). */
  lists?: ListOption[]
  initialLists?: string[]
  busy?: boolean
  onClose: () => void
  onSubmit: (place: { name: string; note: string; lat: number; lon: number }, lists: string[]) => void
}) {
  const { t } = useTranslation()
  const [name, setName] = useState(initial.name)
  const [note, setNote] = useState(initial.note)
  const [lat, setLat] = useState(initial.lat?.toFixed(6) ?? '')
  const [lon, setLon] = useState(initial.lon?.toFixed(6) ?? '')
  const [query, setQuery] = useState('')
  const [chosen, setChosen] = useState<string[]>(initialLists)
  const [cities, setCities] = useState<Awaited<ReturnType<typeof loadCities>> | null>(null)
  const [citiesFailed, setCitiesFailed] = useState(false)

  useEffect(() => {
    if (!open) return
    setName(initial.name)
    setNote(initial.note)
    setLat(initial.lat?.toFixed(6) ?? '')
    setLon(initial.lon?.toFixed(6) ?? '')
    setQuery('')
    setChosen(initialLists)
    // initialLists is read when the dialog opens.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, initial])

  useEffect(() => {
    if (!open || query.trim().length < 2 || cities || citiesFailed) return
    loadCities().then(setCities, () => setCitiesFailed(true))
  }, [open, query, cities, citiesFailed])
  const results = useMemo(() => (cities ? searchCities(cities, query) : []), [cities, query])

  function pickCity(city: City) {
    setLat(city.lat.toFixed(6))
    setLon(city.lon.toFixed(6))
    if (!name.trim()) setName(city.name)
    setQuery('')
  }

  const latValue = Number(lat)
  const lonValue = Number(lon)
  const latBad = lat.trim() === '' || !Number.isFinite(latValue) || latValue < -90 || latValue > 90
  const lonBad = lon.trim() === '' || !Number.isFinite(lonValue) || lonValue < -180 || lonValue > 180
  const nameBad = name.trim().length === 0 || [...name.trim()].length > MAX_NAME
  const noteBad = [...note].length > MAX_NOTE
  const noList = lists !== undefined && chosen.length === 0
  const invalid = latBad || lonBad || nameBad || noteBad || noList

  function submit(event: FormEvent) {
    event.preventDefault()
    if (invalid) return
    onSubmit({ name: name.trim(), note, lat: latValue, lon: lonValue }, chosen)
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-lg">
        <form className="space-y-4" onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>{mode === 'add' ? t('place.addTitle') : t('place.editTitle')}</DialogTitle>
            <DialogDescription>{t('place.description')}</DialogDescription>
          </DialogHeader>
          <Field label={t('place.name')} error={name && nameBad ? t('place.nameInvalid', { max: MAX_NAME }) : undefined} required>
            {(field) => <Input {...field} value={name} onChange={(e) => setName(e.target.value)} autoFocus />}
          </Field>
          <Field label={t('place.note')} error={noteBad ? t('place.noteTooLong', { max: MAX_NOTE }) : undefined}>
            {(field) => <Textarea {...field} value={note} onChange={(e) => setNote(e.target.value)} rows={3} />}
          </Field>
          <div className="space-y-2">
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={t('place.searchCity')}
                aria-label={t('place.searchCity')}
                className="pl-9"
              />
            </div>
            {query.trim().length >= 2 ? (
              citiesFailed ? (
                <p className="text-sm text-destructive">{t('place.citiesFailed')}</p>
              ) : !cities ? (
                <p className="text-sm text-muted-foreground">{t('common.loading')}</p>
              ) : results.length === 0 ? (
                <p className="text-sm text-muted-foreground">{t('place.noCities')}</p>
              ) : (
                <ul className="max-h-40 overflow-y-auto rounded-md border border-border">
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
            <p className="text-xs text-muted-foreground">{t('place.citiesAttribution', { source: CITIES_ATTRIBUTION })}</p>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <Field label={t('place.lat')} error={lat && latBad ? t('place.latInvalid') : undefined} required>
              {(field) => <Input {...field} value={lat} onChange={(e) => setLat(e.target.value)} inputMode="decimal" />}
            </Field>
            <Field label={t('place.lon')} error={lon && lonBad ? t('place.lonInvalid') : undefined} required>
              {(field) => <Input {...field} value={lon} onChange={(e) => setLon(e.target.value)} inputMode="decimal" />}
            </Field>
          </div>
          {lists ? (
            <fieldset className="space-y-2">
              <legend className="text-sm font-medium">{t('place.saveTo')}</legend>
              {lists.length === 0 ? (
                <p className="text-sm text-muted-foreground">{t('place.noLists')}</p>
              ) : (
                <ul className="max-h-40 space-y-1 overflow-y-auto rounded-md border border-border p-2">
                  {lists.map((list) => (
                    <li key={list.id} className="flex items-center gap-2">
                      <Checkbox
                        id={`place-list-${list.id}`}
                        checked={chosen.includes(list.id)}
                        onCheckedChange={(v) => setChosen((c) => (v === true ? [...c, list.id] : c.filter((id) => id !== list.id)))}
                      />
                      <span className="size-2.5 shrink-0 rounded-full" style={{ backgroundColor: list.color }} aria-hidden />
                      <Label htmlFor={`place-list-${list.id}`} className="min-w-0 flex-1 truncate font-normal">
                        {list.title}
                      </Label>
                    </li>
                  ))}
                </ul>
              )}
            </fieldset>
          ) : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={invalid || busy} loading={busy}>
              {mode === 'add' ? t('place.add') : t('place.save')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
