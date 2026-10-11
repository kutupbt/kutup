import { ExternalLink } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { toast } from 'sonner'
import { feedbackIssueBody, feedbackTracker, githubIssueUrl } from '@kutup/session/feedback'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { Card } from '@kutup/ui/components/card'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { Tabs, TabsList, TabsTrigger } from '@kutup/ui/components/tabs'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { formatInstant } from '@kutup/ui/lib/format'
import { useDeleteFeedback, useFeedback, useResolveFeedback, type FeedbackItem } from './api'

/**
 * Feedback sent from the sidebar of the apps (docs/api.md, "Feedback"): bugs,
 * feature requests and anything else. Each is marked done, dismissed, or
 * forwarded to the public tracker, which an administrator does by opening a
 * prefilled issue there after reading it: who sent it never goes into the
 * issue, and the text can be edited before it is submitted.
 */
export function FeedbackPage() {
  const { t } = useTranslation()
  const [status, setStatus] = useState<'open' | 'resolved'>('open')
  const feedback = useFeedback(status)
  const resolve = useResolveFeedback()
  const remove = useDeleteFeedback()
  const [tracker, setTracker] = useState<string | null>(null)
  const [forwarding, setForwarding] = useState<FeedbackItem | null>(null)
  const [deleting, setDeleting] = useState<FeedbackItem | null>(null)

  useEffect(() => {
    feedbackTracker().then(setTracker, () => setTracker(null))
  }, [])

  const mark = (item: FeedbackItem, resolution: 'done' | 'dismissed') =>
    resolve.mutate(
      { id: item.id, resolution },
      {
        onSuccess: () => toast.success(t(`admin.feedback.marked.${resolution}`)),
        onError: (error) => toast.error(apiErrorMessage(error, t('admin.feedback.actionFailed'))),
      },
    )

  function openOnGitHub(item: FeedbackItem) {
    if (!tracker) return
    const title = item.message.split('\n')[0].slice(0, 80)
    window.open(
      githubIssueUrl(tracker, { title, body: feedbackIssueBody(item.message, item.details), kind: item.kind }),
      '_blank',
      'noopener,noreferrer',
    )
    setForwarding(item)
  }

  return (
    <PageBody>
      <PageHeader title={t('admin.feedback.title')} description={t('admin.feedback.description')} />
      <Tabs value={status} onValueChange={(v) => setStatus(v as 'open' | 'resolved')}>
        <TabsList>
          <TabsTrigger value="open">{t('admin.feedback.open')}</TabsTrigger>
          <TabsTrigger value="resolved">{t('admin.feedback.resolved')}</TabsTrigger>
        </TabsList>
      </Tabs>
      {feedback.isPending ? <LoadingPanel label={t('common.loading')} /> : null}
      {feedback.isError ? <Alert variant="error">{apiErrorMessage(feedback.error, t('common.tryAgain'))}</Alert> : null}
      {feedback.data && feedback.data.length === 0 ? (
        <EmptyState
          title={t(status === 'open' ? 'admin.feedback.emptyTitle' : 'admin.feedback.noneResolvedTitle')}
          description={t(status === 'open' ? 'admin.feedback.emptyDescription' : 'admin.feedback.noneResolvedDescription')}
        />
      ) : null}
      <ul className="space-y-3">
        {feedback.data?.map((item) => (
          <li key={item.id}>
            <FeedbackCard
              item={item}
              tracker={tracker}
              busy={resolve.isPending && resolve.variables?.id === item.id}
              onDone={() => mark(item, 'done')}
              onDismiss={() => mark(item, 'dismissed')}
              onGitHub={() => openOnGitHub(item)}
              onDelete={() => setDeleting(item)}
            />
          </li>
        ))}
      </ul>
      {forwarding && tracker ? (
        <ForwardDialog
          item={forwarding}
          tracker={tracker}
          onClose={() => setForwarding(null)}
          onForwarded={(githubUrl) =>
            resolve.mutate(
              { id: forwarding.id, resolution: 'forwarded', githubUrl: githubUrl || undefined },
              {
                onSuccess: () => {
                  toast.success(t('admin.feedback.marked.forwarded'))
                  setForwarding(null)
                },
                onError: (error) => toast.error(apiErrorMessage(error, t('admin.feedback.actionFailed'))),
              },
            )
          }
          pending={resolve.isPending}
        />
      ) : null}
      {deleting ? (
        <ConfirmDestructive
          open
          onOpenChange={(o) => {
            if (!o) {
              setDeleting(null)
              remove.reset()
            }
          }}
          title={t('admin.feedback.deleteTitle')}
          description={t('admin.feedback.deleteDescription')}
          submit={t('admin.feedback.delete')}
          pending={remove.isPending}
          error={remove.error}
          errorFallback={t('admin.feedback.actionFailed')}
          onConfirm={() =>
            remove.mutate(deleting.id, {
              onSuccess: () => {
                toast.success(t('admin.feedback.deleted'))
                setDeleting(null)
              },
            })
          }
        />
      ) : null}
    </PageBody>
  )
}

const DETAIL_ORDER = ['version', 'browser', 'language', 'screen'] as const

const KIND_VARIANT = { bug: 'warn', feature: 'ok', other: 'outline' } as const

function FeedbackCard({
  item,
  tracker,
  busy,
  onDone,
  onDismiss,
  onGitHub,
  onDelete,
}: {
  item: FeedbackItem
  tracker: string | null
  busy: boolean
  onDone: () => void
  onDismiss: () => void
  onGitHub: () => void
  onDelete: () => void
}) {
  const { t, i18n } = useTranslation()
  const open = item.resolvedAt === null
  return (
    <Card className="space-y-3 p-4" data-testid="feedback-item">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={KIND_VARIANT[item.kind]}>{t(`feedback.kinds.${item.kind}`)}</Badge>
        <span className="text-sm text-muted-foreground">
          {t(`apps.${item.app}`, { defaultValue: item.app })} · {formatInstant(item.createdAt, i18n.language)}
        </span>
        {item.resolution ? (
          <Badge variant="neutral" className="ml-auto">
            {t(`admin.feedback.resolution.${item.resolution}`)}
          </Badge>
        ) : null}
      </div>
      <p className="whitespace-pre-wrap break-words text-sm">{item.message}</p>
      <dl className="grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[max-content_1fr]">
        <dt className="text-muted-foreground">{t('admin.feedback.from')}</dt>
        <dd className="min-w-0 truncate">
          {item.userId ? (
            <Link to={`/admin/users/${item.userId}`} className="font-medium hover:underline">
              {item.userEmail}
            </Link>
          ) : (
            <span className="text-muted-foreground">{t('admin.feedback.deletedAccount')}</span>
          )}
        </dd>
        {DETAIL_ORDER.filter((key) => item.details?.[key]).map((key) => [key, item.details![key]!] as const).map(([key, value]) => (
          <div key={key} className="contents">
            <dt className="text-muted-foreground">{t(`feedback.detail.${key}`, { defaultValue: key })}</dt>
            <dd className="min-w-0 break-words text-muted-foreground">{value}</dd>
          </div>
        ))}
        {item.githubUrl ? (
          <>
            <dt className="text-muted-foreground">{t('admin.feedback.issue')}</dt>
            <dd>
              <a href={item.githubUrl} target="_blank" rel="noopener noreferrer" className="font-medium text-primary hover:underline">
                {item.githubUrl.replace('https://github.com/', '')}
              </a>
            </dd>
          </>
        ) : null}
      </dl>
      <div className="flex flex-wrap gap-2 border-t border-border pt-3">
        {open && tracker ? (
          <Button size="sm" variant="outline" onClick={onGitHub}>
            <ExternalLink /> {t('admin.feedback.openOnGitHub')}
          </Button>
        ) : null}
        <div className="ml-auto flex flex-wrap gap-2">
          {open ? (
            <>
              <Button size="sm" variant="ghost" loading={busy} onClick={onDismiss}>
                {t('admin.feedback.dismiss')}
              </Button>
              <Button size="sm" variant="outline" loading={busy} onClick={onDone}>
                {t('admin.feedback.done')}
              </Button>
            </>
          ) : null}
          <Button size="sm" variant="ghost" className="text-destructive" onClick={onDelete}>
            {t('admin.feedback.delete')}
          </Button>
        </div>
      </div>
    </Card>
  )
}

/**
 * After the prefilled issue opened in a new tab: record the issue it became,
 * so the feedback links to it. The address is optional; an issue not made
 * after all can be left out.
 */
function ForwardDialog({
  item,
  tracker,
  pending,
  onClose,
  onForwarded,
}: {
  item: FeedbackItem
  tracker: string
  pending: boolean
  onClose: () => void
  onForwarded: (githubUrl: string) => void
}) {
  const { t } = useTranslation()
  const [url, setUrl] = useState('')
  const trimmed = url.trim()
  const prefix = `https://github.com/${tracker}/issues/`
  const invalid = trimmed !== '' && !(trimmed.toLowerCase().startsWith(prefix.toLowerCase()) && /^\d+$/.test(trimmed.slice(prefix.length)))
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-md" data-feedback-id={item.id}>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            if (!invalid) onForwarded(trimmed)
          }}
        >
          <DialogHeader>
            <DialogTitle>{t('admin.feedback.forwardTitle')}</DialogTitle>
            <DialogDescription>{t('admin.feedback.forwardDescription', { repository: tracker })}</DialogDescription>
          </DialogHeader>
          <Field label={t('admin.feedback.issueUrl')} error={invalid ? t('admin.feedback.issueUrlInvalid', { prefix }) : undefined}>
            {(props) => <Input {...props} autoFocus value={url} placeholder={`${prefix}123`} onChange={(e) => setUrl(e.target.value)} />}
          </Field>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={pending} disabled={invalid}>
              {t('admin.feedback.markForwarded')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
