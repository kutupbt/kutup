import { ArrowRight, Loader2, MessageSquare, X } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { toast } from 'sonner'
import { addPlace, listTitle, placesOf, removePlace } from '@kutup/map/list'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { formatFileDate } from '@kutup/ui/lib/format'
import { PersonName } from '../people/PersonName'
import { samePlace, useAtlas } from './atlasContext'
import { sendToChat } from './chat'
import type { ListEntry } from './lists'

/**
 * A chosen place, over the map's right side: its name, note and who added
 * it, and every list it is in — ticked lists can be unticked to take it out,
 * others ticked to put it in (as Google Maps' "Saved in"). One place keeps
 * one id across lists.
 */
export function PlaceCard() {
  const { t, i18n } = useTranslation()
  const atlas = useAtlas()
  const [busy, setBusy] = useState<string | null>(null)
  const shown = atlas.shown
  if (!shown) return null
  const { place } = shown

  const rows = atlas.lists
    .map((entry) => {
      const places = atlas.placesOf(entry.file.id)
      return { entry, known: places !== undefined, inIt: places?.some((p) => samePlace(p, place)) ?? false, editable: atlas.editable(entry) }
    })
    // Lists it is in, and lists it could go into.
    .filter((row) => row.inIt || row.editable)
    .sort((a, b) => Number(b.inIt) - Number(a.inIt) || listTitle(a.entry.file.name ?? '').localeCompare(listTitle(b.entry.file.name ?? '')))

  async function toggle(entry: ListEntry, add: boolean) {
    if (!atlas.me) return
    const title = listTitle(entry.file.name ?? '')
    setBusy(entry.file.id)
    try {
      await atlas.write(entry, (doc) => {
        if (add) {
          addPlace(doc, { ...place, addedBy: atlas.me!, addedAt: new Date().toISOString() })
        } else {
          for (const p of placesOf(doc)) if (samePlace(p, place)) removePlace(doc, p.id)
        }
      })
      toast.success(add ? t('card.added', { list: title }) : t('card.removed', { list: title }))
    } catch {
      toast.error(t('card.failed', { list: title }))
    } finally {
      setBusy(null)
    }
  }

  return (
    <section
      className="absolute inset-x-3 top-3 z-20 flex max-h-[calc(100%-1.5rem)] flex-col overflow-hidden rounded-xl border border-border bg-background shadow-xl md:left-auto md:right-14 md:w-80"
      aria-label={t('card.label', { name: place.name })}
      data-testid="place-card"
    >
      <header className="flex items-start gap-2 border-b border-border px-4 py-3">
        <div className="min-w-0 flex-1">
          <h2 className="break-words font-semibold">{place.name}</h2>
          <p className="font-mono text-xs text-muted-foreground">
            {place.lat.toFixed(5)}, {place.lon.toFixed(5)}
          </p>
        </div>
        <Button variant="ghost" size="icon" className="-mr-2 size-8" onClick={() => atlas.showPlace(null)} aria-label={t('card.close')}>
          <X />
        </Button>
      </header>
      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-4 py-3">
        {place.note ? <p className="whitespace-pre-wrap break-words text-sm">{place.note}</p> : null}
        {place.addedBy ? (
          <p className="text-xs text-muted-foreground">
            <PersonName
              account={place.addedBy}
              avatar={false}
              format={(name) => t('list.addedBy', { name, date: formatFileDate(place.addedAt, i18n.language) })}
            />
          </p>
        ) : null}
        <div className="space-y-2">
          <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{t('card.lists')}</h3>
          {rows.length === 0 ? <p className="text-sm text-muted-foreground">{t('card.noLists')}</p> : null}
          <ul className="space-y-1">
            {rows.map(({ entry, known, inIt, editable }) => {
              const id = `card-list-${entry.file.id}`
              const title = listTitle(entry.file.name ?? '')
              return (
                <li key={entry.file.id} className="flex items-center gap-2">
                  {busy === entry.file.id ? (
                    <Loader2 className="size-4 animate-spin text-muted-foreground" aria-hidden />
                  ) : (
                    <Checkbox
                      id={id}
                      checked={inIt}
                      disabled={!editable || !known || busy !== null}
                      onCheckedChange={(v) => void toggle(entry, v === true)}
                    />
                  )}
                  <span className="size-2.5 shrink-0 rounded-full" style={{ backgroundColor: atlas.colorOf(entry.file.id) }} aria-hidden />
                  <label htmlFor={id} className="min-w-0 flex-1 truncate text-sm">
                    {title}
                    {!editable ? <span className="ml-1 text-xs text-muted-foreground">{t('card.viewOnly')}</span> : null}
                  </label>
                  {inIt && entry.file.id !== atlas.open?.fileId ? (
                    <Button variant="ghost" size="icon" className="size-7" asChild>
                      <Link to={entry.path} state={{ place: place.id }} aria-label={t('card.openList', { list: title })} title={t('card.openList', { list: title })}>
                        <ArrowRight />
                      </Link>
                    </Button>
                  ) : null}
                </li>
              )
            })}
          </ul>
        </div>
      </div>
      <footer className="border-t border-border px-4 py-3">
        <Button variant="outline" size="sm" className="w-full" onClick={() => sendToChat(place)}>
          <MessageSquare /> {t('list.sendToChat')}
        </Button>
      </footer>
    </section>
  )
}
