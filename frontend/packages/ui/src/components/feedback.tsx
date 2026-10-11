import { ExternalLink, MessageSquareText } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { apiErrorMessage } from '../lib/apiError'
import { cn } from '../lib/cn'
import { Button } from './button'
import { Checkbox } from './checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './dialog'
import { Field } from './field'
import { Label } from './label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './select'
import { Textarea } from './textarea'

type Kind = 'bug' | 'feature' | 'other'
type Details = Partial<Record<'version' | 'browser' | 'language' | 'screen', string>>

/** What the form needs from the session (`@kutup/session/feedback`), passed in: this package knows no server. */
export interface FeedbackServices {
  sendFeedback: (input: { kind: Kind; app: string; message: string; details?: Details }) => Promise<void>
  feedbackTracker: () => Promise<string | null>
  collectFeedbackDetails: () => Details
  githubIssueUrl: (repository: string, issue: { title: string; body: string; kind?: Kind }) => string
  feedbackIssueBody: (message: string, details?: Details | null) => string
}

const MAX = 5000

/**
 * "Send feedback" at the foot of every app's sidebar: a bug, a feature
 * request or anything else, to this server's administrators. They may
 * forward it to the public tracker after reading it; whoever prefers to
 * report there in public can open it from the form instead.
 */
export function FeedbackButton({ app, services, className }: { app: string; services: FeedbackServices; className?: string }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        data-testid="feedback-open"
        className={cn(
          'flex h-8 w-full items-center gap-3 rounded-md px-3 text-sm text-chrome-muted transition-colors',
          'hover:bg-chrome-accent/60 hover:text-chrome-foreground',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-chrome-active [&_svg]:size-4 [&_svg]:shrink-0',
          className,
        )}
      >
        <MessageSquareText aria-hidden />
        <span className="truncate">{t('feedback.open')}</span>
      </button>
      {open ? <FeedbackDialog app={app} services={services} onClose={() => setOpen(false)} /> : null}
    </>
  )
}

function FeedbackDialog({ app, services, onClose }: { app: string; services: FeedbackServices; onClose: () => void }) {
  const { t } = useTranslation()
  const [kind, setKind] = useState<Kind>('bug')
  const [message, setMessage] = useState('')
  const [withDetails, setWithDetails] = useState(true)
  const [details] = useState(() => services.collectFeedbackDetails())
  const [tracker, setTracker] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let current = true
    services.feedbackTracker().then(
      (repository) => current && setTracker(repository),
      () => undefined,
    )
    return () => {
      current = false
    }
  }, [services])

  const trimmed = message.trim()
  const shown = withDetails ? details : undefined

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!trimmed || pending) return
    setPending(true)
    setError(null)
    try {
      await services.sendFeedback({ kind, app, message: trimmed, details: shown })
      toast.success(t('feedback.sent'))
      onClose()
    } catch (e) {
      setError(apiErrorMessage(e, t('feedback.failed')))
    } finally {
      setPending(false)
    }
  }

  function openOnGitHub() {
    if (!tracker) return
    const title = trimmed.split('\n')[0].slice(0, 80) || t(`feedback.kinds.${kind}`)
    const url = services.githubIssueUrl(tracker, { title, body: services.feedbackIssueBody(trimmed, shown), kind })
    window.open(url, '_blank', 'noopener,noreferrer')
  }

  return (
    <Dialog open onOpenChange={(next) => !next && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <form onSubmit={(event) => void submit(event)} className="space-y-4">
          <DialogHeader>
            <DialogTitle>{t('feedback.title')}</DialogTitle>
            <DialogDescription>{t('feedback.description')}</DialogDescription>
          </DialogHeader>
          <Field label={t('feedback.kind')}>
            {(props) => (
              <Select value={kind} onValueChange={(value) => setKind(value as Kind)}>
                <SelectTrigger id={props.id} aria-describedby={props['aria-describedby']}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(['bug', 'feature', 'other'] as const).map((value) => (
                    <SelectItem key={value} value={value}>
                      {t(`feedback.kinds.${value}`)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </Field>
          <Field label={t(`feedback.messageLabel.${kind}`)} description={t('feedback.privacy')} error={error ?? undefined}>
            {(props) => (
              <Textarea
                {...props}
                autoFocus
                rows={6}
                maxLength={MAX}
                value={message}
                onChange={(e) => {
                  setMessage(e.target.value)
                  setError(null)
                }}
              />
            )}
          </Field>
          <div className="space-y-2">
            <div className="flex items-start gap-2">
              <Checkbox id="feedback-details" checked={withDetails} onCheckedChange={(value) => setWithDetails(value === true)} />
              <Label htmlFor="feedback-details" className="leading-snug">
                {t('feedback.includeDetails')}
              </Label>
            </div>
            {withDetails ? (
              <dl className="ml-6 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 rounded-md bg-muted/50 px-3 py-2 text-xs text-muted-foreground" data-testid="feedback-details">
                {Object.entries(details).map(([key, value]) => (
                  <div key={key} className="contents">
                    <dt className="font-medium">{t(`feedback.detail.${key}`)}</dt>
                    <dd className="min-w-0 break-words">{value}</dd>
                  </div>
                ))}
              </dl>
            ) : null}
          </div>
          <DialogFooter className="sm:justify-between">
            {tracker ? (
              <Button type="button" variant="ghost" size="sm" onClick={openOnGitHub} disabled={!trimmed} title={t('feedback.githubHint')}>
                <ExternalLink />
                {t('feedback.github')}
              </Button>
            ) : (
              <span />
            )}
            <div className="flex flex-col-reverse gap-2 sm:flex-row">
              <Button type="button" variant="outline" onClick={onClose}>
                {t('common.cancel')}
              </Button>
              <Button type="submit" loading={pending} disabled={!trimmed}>
                {t('feedback.send')}
              </Button>
            </div>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
