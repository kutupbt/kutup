import { useQueryClient } from '@tanstack/react-query'
import { lazy, Suspense, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { Textarea } from '@kutup/ui/components/textarea'
import { writeMedia } from '../library/catchUp'
import { formatOffset } from '../library/format'
import type { Photo } from '../library/library'
import { takenParts } from '../library/timeline'
import { editedMedia } from './editedMedia'

const MapView = lazy(() => import('@kutup/map/MapView').then((m) => ({ default: m.MapView })))

/** Time zones in quarter hours, UTC−12:00 to UTC+14:00. */
const OFFSETS = Array.from({ length: (14 + 12) * 4 + 1 }, (_, i) => -12 * 60 + i * 15)

const pad = (n: number) => String(n).padStart(2, '0')

/** "2024-07-01T19:45", the clock where it was taken (or this device's). */
function wallClock(photo: Photo): string {
  const p = takenParts(photo)
  return `${p.year}-${pad(p.month)}-${pad(p.day)}T${pad(p.hour)}:${pad(p.minute)}`
}

/**
 * Change when and where a photo was taken, and its caption: a new metadata
 * revision, sealed on this device (only for photos this account may write).
 */
export function EditDetailsDialog({ photo, open, onClose }: { photo: Photo; open: boolean; onClose: () => void }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const deviceOffset = -new Date(photo.takenAt).getTimezoneOffset()
  const originalWhen = wallClock(photo)
  const [when, setWhen] = useState(originalWhen)
  const [offset, setOffset] = useState(photo.takenOffset ?? deviceOffset)
  const [lat, setLat] = useState('')
  const [lon, setLon] = useState('')
  const [caption, setCaption] = useState('')
  const [saving, setSaving] = useState(false)
  const [invalid, setInvalid] = useState(false)

  useEffect(() => {
    if (!open) return
    setWhen(originalWhen)
    setOffset(photo.takenOffset ?? deviceOffset)
    setLat(photo.media?.lat !== undefined ? String(photo.media.lat) : '')
    setLon(photo.media?.lon !== undefined ? String(photo.media.lon) : '')
    setCaption(photo.media?.caption ?? '')
    setInvalid(false)
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset each time it opens
  }, [open, photo.id])

  async function save() {
    const next = editedMedia(photo.media, { when, offset, lat, lon, caption }, photo.dated, originalWhen, photo.takenOffset)
    if (!next) {
      setInvalid(true)
      return
    }
    setSaving(true)
    try {
      await writeMedia(photo.file, Object.keys(next).length ? next : null)
      await queryClient.invalidateQueries({ queryKey: ['files'] })
      toast.success(t('edit.saved'))
      onClose()
    } catch {
      toast.error(t('edit.failed'))
    } finally {
      setSaving(false)
    }
  }

  const point = Number.isFinite(Number(lat)) && Number.isFinite(Number(lon)) && lat && lon ? { lat: Number(lat), lon: Number(lon) } : null
  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t('edit.title')}</DialogTitle>
          <DialogDescription>{t('edit.description')}</DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            void save()
          }}
        >
          <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
            <Field label={t('edit.when')}>
              {(field) => <Input {...field} type="datetime-local" value={when} onChange={(e) => setWhen(e.target.value)} />}
            </Field>
            <Field label={t('edit.zone')}>
              {(field) => (
                <Select value={String(offset)} onValueChange={(v) => setOffset(Number(v))}>
                  <SelectTrigger id={field.id} aria-describedby={field['aria-describedby']} className="sm:w-40">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {OFFSETS.map((o) => (
                      <SelectItem key={o} value={String(o)}>
                        {formatOffset(o)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </Field>
          </div>
          <div className="space-y-2">
            <div className="grid grid-cols-2 gap-3">
              <Field label={t('edit.latitude')}>
                {(field) => <Input {...field} inputMode="decimal" value={lat} onChange={(e) => setLat(e.target.value)} />}
              </Field>
              <Field label={t('edit.longitude')}>
                {(field) => <Input {...field} inputMode="decimal" value={lon} onChange={(e) => setLon(e.target.value)} />}
              </Field>
            </div>
            <div className="h-40 overflow-hidden rounded-lg border border-border">
              <Suspense fallback={null}>
                <MapView
                  center={point ?? { lat: 20, lon: 0 }}
                  zoom={point ? 12 : 1}
                  markers={point ? [point] : []}
                  onPick={(p) => {
                    setLat(p.lat.toFixed(6))
                    setLon(p.lon.toFixed(6))
                  }}
                  fallback={<p className="flex h-full items-center justify-center px-4 text-center text-xs text-muted-foreground">{t('edit.mapsOff')}</p>}
                  className="h-40 w-full"
                  ariaLabel={t('edit.pickOnMap')}
                />
              </Suspense>
            </div>
            <div className="flex items-center justify-between gap-2">
              <p className="text-xs text-muted-foreground">{t('edit.pickHint')}</p>
              {lat || lon ? (
                <Button type="button" variant="ghost" size="sm" onClick={() => (setLat(''), setLon(''))}>
                  {t('edit.removePlace')}
                </Button>
              ) : null}
            </div>
          </div>
          <Field label={t('edit.caption')}>
            {(field) => <Textarea {...field} value={caption} maxLength={2000} rows={3} onChange={(e) => setCaption(e.target.value)} />}
          </Field>
          {invalid ? <p className="text-sm text-destructive">{t('edit.invalid')}</p> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={saving}>
              {saving ? t('edit.saving') : t('common.save')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
