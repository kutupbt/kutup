import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { FOLDERS, useSearchAddresses } from '@kutup/mail-core/api'
import { usePlaces } from '@kutup/mail-core/places'
import { EMPTY_SEARCH, searchFromParams, searchToParams, type AdvancedSearch as Search } from '@kutup/mail-core/search'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { useMailboxScope } from './mailboxScope'

const ALL_ADDRESSES = '*'

/** The place the route shows, as the form's Location: `all`, a folder id, `folder:<id>` or `label:<id>`. */
function currentPlace(pathname: string, folder: string | undefined): string {
  const own = /^\/(f|l)\/([^/]+)/.exec(pathname)
  if (own) return `${own[1] === 'f' ? 'folder' : 'label'}:${own[2]}`
  return folder && (FOLDERS as string[]).concat('all').includes(folder) ? folder : 'all'
}

/**
 * Proton's advanced search: a keyword, where to look, a date range, the
 * sender, a recipient, which address, and "has attachments"; the search
 * goes to the address bar of the place chosen.
 */
export function AdvancedSearch({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const location = useLocation()
  const { folder } = useParams()
  const [params] = useSearchParams()
  const scope = useMailboxScope()
  const places = usePlaces()
  const addresses = useSearchAddresses(scope.group)
  const [model, setModel] = useState<Search>(() => searchFromParams(params))
  const [place, setPlace] = useState(() => currentPlace(location.pathname, folder))
  const set = (change: Partial<Search>) => setModel((before) => ({ ...before, ...change }))
  // A shared mailbox has no drafts, and your own folders and labels are in your own mailbox only.
  const fixed = ['all', ...FOLDERS.filter((f) => !(scope.group && f === 'drafts'))]

  const go = (search: Search, to: string) => {
    const path = to.startsWith('folder:') ? `/f/${to.slice(7)}` : to.startsWith('label:') ? `/l/${to.slice(6)}` : `${scope.base}/${to}`
    const query = searchToParams(search).toString()
    void navigate(query ? `${path}?${query}` : path)
    onDone()
  }
  const submit = (event: FormEvent) => {
    event.preventDefault()
    go(model, place)
  }

  return (
    <form className="grid gap-3" aria-label={t('search.advanced')} onSubmit={submit} onReset={(event) => {
      event.preventDefault()
      setModel(EMPTY_SEARCH)
      go(EMPTY_SEARCH, place)
    }}>
      <div className="grid gap-1.5">
        <Label htmlFor="search-keyword">{t('search.keyword')}</Label>
        <Input id="search-keyword" type="search" value={model.q} onChange={(e) => set({ q: e.target.value })} placeholder={t('search.placeholder')} autoFocus />
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="search-location">{t('search.location')}</Label>
        <Select value={place} onValueChange={setPlace}>
          <SelectTrigger id="search-location">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {fixed.map((id) => (
              <SelectItem key={id} value={id}>
                {t(`folders.${id}`)}
              </SelectItem>
            ))}
            {scope.group
              ? null
              : [...(places.data?.folders.values() ?? [])].map((f) => (
                  <SelectItem key={f.id} value={`folder:${f.id}`}>
                    {f.name}
                  </SelectItem>
                ))}
            {scope.group
              ? null
              : (places.data?.labels ?? []).map((l) => (
                  <SelectItem key={l.id} value={`label:${l.id}`}>
                    {l.name}
                  </SelectItem>
                ))}
          </SelectContent>
        </Select>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div className="grid gap-1.5">
          <Label htmlFor="search-since">{t('search.since')}</Label>
          <Input id="search-since" type="date" value={model.since} max={model.until || undefined} onChange={(e) => set({ since: e.target.value })} />
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="search-until">{t('search.until')}</Label>
          <Input id="search-until" type="date" value={model.until} min={model.since || undefined} onChange={(e) => set({ until: e.target.value })} />
        </div>
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="search-from">{t('search.from')}</Label>
        <Input id="search-from" value={model.from} onChange={(e) => set({ from: e.target.value })} placeholder={t('search.personPlaceholder')} />
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="search-to">{t('search.to')}</Label>
        <Input id="search-to" value={model.to} onChange={(e) => set({ to: e.target.value })} placeholder={t('search.personPlaceholder')} />
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="search-address">{t('search.address')}</Label>
        <Select value={model.address || ALL_ADDRESSES} onValueChange={(value) => set({ address: value === ALL_ADDRESSES ? '' : value })}>
          <SelectTrigger id="search-address">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL_ADDRESSES}>{t('search.allAddresses')}</SelectItem>
            {(addresses.data ?? []).map((address) => (
              <SelectItem key={address} value={address}>
                {address}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <label className="flex items-center gap-2 text-sm">
        <Checkbox checked={model.attachments} onCheckedChange={(on) => set({ attachments: on === true })} />
        {t('search.hasAttachments')}
      </label>
      <div className="flex justify-end gap-2 pt-1">
        <Button type="reset" variant="ghost">
          {t('search.reset')}
        </Button>
        <Button type="submit">{t('search.submit')}</Button>
      </div>
    </form>
  )
}
