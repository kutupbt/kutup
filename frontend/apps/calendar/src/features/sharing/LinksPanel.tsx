import { Copy, Link2, Plus, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useQuery } from '@tanstack/react-query'
import { useCalendarMutation, type Calendar } from '@kutup/calendar-core/api'
import { useMailAccount } from '@kutup/mail-core/api'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { createLink, deleteLink, linkPurpose, loadLinks, loadSharingSettings, MAX_LINK_PURPOSE, showLink, TooManyLinks, type LinkKind, type LinkRow, type LinkUrls } from './client'

async function copy(text: string, done: string, failed: string) {
  try {
    await navigator.clipboard.writeText(text)
    toast.success(done)
  } catch {
    toast.error(failed)
  }
}

/** A link's URLs, each with its copy button; `prefix` keeps several on one page apart. */
export function UrlFields({ urls, prefix = 'link' }: { urls: LinkUrls; prefix?: string }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-3">
      {(['page', 'ics'] as const).map((which) =>
        urls[which] ? (
          <div key={which} className="space-y-1.5">
            <Label htmlFor={`${prefix}-${which}`}>{t(`sharing.links.url.${which}`)}</Label>
            <div className="flex gap-2">
              <Input id={`${prefix}-${which}`} readOnly value={urls[which]} onFocus={(e) => e.currentTarget.select()} className="font-mono text-xs" data-testid={`${prefix}-url-${which}`} />
              <Button
                type="button"
                variant="outline"
                size="icon"
                aria-label={t(`sharing.links.copy.${which}`)}
                onClick={() => void copy(urls[which]!, t('sharing.links.copied'), t('sharing.links.copyFailed'))}
              >
                <Copy />
              </Button>
            </div>
          </div>
        ) : null,
      )}
    </div>
  )
}

/** The calendar's links (Proton's `CalendarShareUrlSection`): each kind said plainly, copied again, deleted. */
export function LinksPanel({ calendar }: { calendar: Calendar }) {
  const { t, i18n } = useTranslation()
  const session = useRequiredSession()
  const account = useMailAccount()
  const links = useQuery({ queryKey: ['calendar', 'links', calendar.id], queryFn: () => loadLinks(calendar.id) })
  const settings = useQuery({ queryKey: ['calendar', 'sharing-settings'], queryFn: loadSharingSettings, staleTime: Infinity })
  const [creating, setCreating] = useState(false)
  const [deleting, setDeleting] = useState<LinkRow | null>(null)
  const show = useCalendarMutation((link: LinkRow) => showLink(session, calendar, link))
  const remove = useCalendarMutation((link: LinkRow) => deleteLink(calendar.id, link.id))
  const [shown, setShown] = useState<{ link: LinkRow; urls: LinkUrls } | null>(null)
  const full = settings.data ? (links.data?.length ?? 0) >= settings.data.linksPerCalendar : false

  return (
    <div className="mt-4 space-y-4">
      <p className="text-sm text-muted-foreground">{t('sharing.links.description')}</p>
      {links.isPending ? (
        <p className="text-sm text-muted-foreground">{t('common.loading')}</p>
      ) : links.isError ? (
        <Alert variant="error">{apiErrorMessage(links.error, t('sharing.errors.loadFailed'))}</Alert>
      ) : links.data.length ? (
        <ul className="divide-y divide-border rounded-md border border-border" data-testid="calendar-links">
          {links.data.map((link) => (
            <li key={link.id} className="flex flex-wrap items-center gap-2 px-3 py-2">
              <Link2 className="size-4 text-muted-foreground" aria-hidden />
              <span className="min-w-0 flex-1 text-sm">
                {(account.data && linkPurpose(account.data, calendar, link)) ?? t(`sharing.links.kind.${link.kind}.name`)}
                <span className="block text-xs text-muted-foreground">
                  {account.data && linkPurpose(account.data, calendar, link) ? `${t(`sharing.links.kind.${link.kind}.name`)} · ` : ''}
                  {t('sharing.links.created', { date: new Date(link.createdAt).toLocaleDateString(i18n.language) })}
                </span>
              </span>
              <Button
                variant="outline"
                size="sm"
                loading={show.isPending && show.variables?.id === link.id}
                onClick={() =>
                  show.mutate(link, {
                    onSuccess: (urls) => setShown({ link, urls }),
                    onError: (e) => toast.error(apiErrorMessage(e, t('sharing.links.showFailed'))),
                  })
                }
              >
                <Copy />
                {t('sharing.links.show')}
              </Button>
              <Button variant="ghost" size="icon" className="size-8" aria-label={t('sharing.links.delete')} onClick={() => setDeleting(link)}>
                <Trash2 />
              </Button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-muted-foreground">{t('sharing.links.none')}</p>
      )}
      <Button onClick={() => setCreating(true)} disabled={full || !settings.data} data-testid="link-create">
        <Plus />
        {t('sharing.links.create')}
      </Button>
      {full && settings.data ? <p className="text-xs text-muted-foreground">{t('sharing.links.full', { count: settings.data.linksPerCalendar })}</p> : null}

      {creating && settings.data ? (
        <CreateLinkDialog calendar={calendar} queryAllowed={settings.data.queryLinksAllowed} onClose={() => setCreating(false)} />
      ) : null}
      <Dialog open={shown !== null} onOpenChange={(o) => !o && setShown(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{shown ? t(`sharing.links.kind.${shown.link.kind}.name`) : ''}</DialogTitle>
            <DialogDescription>{shown ? t(`sharing.links.kind.${shown.link.kind}.after`) : ''}</DialogDescription>
          </DialogHeader>
          {shown ? <UrlFields urls={shown.urls} /> : null}
        </DialogContent>
      </Dialog>
      <ConfirmDestructive
        open={deleting !== null}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={t('sharing.links.deleteTitle')}
        description={t('sharing.links.deleteDescription')}
        submit={t('sharing.links.delete')}
        pending={remove.isPending}
        error={remove.error}
        errorFallback={t('sharing.errors.saveFailed')}
        onConfirm={() =>
          deleting &&
          remove.mutate(deleting, {
            onSuccess: () => {
              setDeleting(null)
              toast.success(t('sharing.links.deleted'))
            },
          })
        }
      />
    </div>
  )
}

/**
 * Proton's `ShareLinkModal`: what a link shows, chosen up front. Busy times
 * only is the default, as Proton's limited view; a full link keeps its key in
 * the fragment, which the server never sees; the query kind, for other
 * calendar apps, says plainly that the server reads the calendar on each
 * fetch, and is offered only where the administrator allows it.
 */
function CreateLinkDialog({ calendar, queryAllowed, onClose }: { calendar: Calendar; queryAllowed: boolean; onClose: () => void }) {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const account = useMailAccount()
  const [kind, setKind] = useState<LinkKind>('busy')
  const [label, setLabel] = useState('')
  const make = useCalendarMutation((k: LinkKind) => createLink(session, account.data!, calendar, k, label))
  const kinds: LinkKind[] = queryAllowed ? ['busy', 'full', 'query'] : ['busy', 'full']

  return (
    <Dialog open onOpenChange={(o) => !o && !make.isPending && onClose()}>
      <DialogContent data-testid="link-dialog">
        <DialogHeader>
          <DialogTitle>{make.data ? t(`sharing.links.kind.${kind}.name`) : t('sharing.links.createTitle')}</DialogTitle>
          <DialogDescription>{make.data ? t(`sharing.links.kind.${kind}.after`) : t('sharing.links.createDescription')}</DialogDescription>
        </DialogHeader>
        {make.data ? (
          <UrlFields urls={make.data.urls} />
        ) : (
          <fieldset className="space-y-2">
            <legend className="sr-only">{t('sharing.links.kindLabel')}</legend>
            {kinds.map((k) => (
              <label key={k} className="flex cursor-pointer gap-3 rounded-md border border-border p-3 has-[:checked]:border-primary">
                <input type="radio" name="link-kind" value={k} checked={kind === k} onChange={() => setKind(k)} className="mt-1" data-testid={`link-kind-${k}`} />
                <span className="space-y-1">
                  <span className="block text-sm font-medium">{t(`sharing.links.kind.${k}.name`)}</span>
                  <span className="block text-xs text-muted-foreground">{t(`sharing.links.kind.${k}.hint`)}</span>
                </span>
              </label>
            ))}
            {kind === 'query' ? (
              <Alert variant="warn" title={t('sharing.links.kind.query.warningTitle')}>
                {t('sharing.links.kind.query.warning')}
              </Alert>
            ) : null}
            <div className="space-y-1.5 pt-2">
              <Label htmlFor="link-label">{t('sharing.links.label')}</Label>
              <Input
                id="link-label"
                value={label}
                maxLength={MAX_LINK_PURPOSE}
                placeholder={t('sharing.links.labelPlaceholder')}
                onChange={(e) => setLabel(e.target.value)}
                aria-describedby="link-label-hint"
                data-testid="link-label"
              />
              <p id="link-label-hint" className="text-xs text-muted-foreground">
                {t('sharing.links.labelHint')}
              </p>
            </div>
          </fieldset>
        )}
        {make.error ? (
          <Alert variant="error">
            {make.error instanceof TooManyLinks ? t('sharing.links.full', { count: make.error.limit }) : apiErrorMessage(make.error, t('sharing.links.createFailed'))}
          </Alert>
        ) : null}
        <DialogFooter>
          {make.data ? (
            <Button onClick={onClose}>{t('sharing.links.done')}</Button>
          ) : (
            <>
              <Button variant="ghost" onClick={onClose} disabled={make.isPending}>
                {t('common.cancel')}
              </Button>
              <Button loading={make.isPending} disabled={!account.data} onClick={() => make.mutate(kind)} data-testid="link-create-submit">
                {t('sharing.links.createSubmit')}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
