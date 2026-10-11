import { Ban, OctagonAlert, ShieldCheck, Trash2 } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import {
  isSenderPattern,
  useDeleteSenderRules,
  useSenderRules,
  useSetSenderRules,
  useUpdateSenderRule,
  type SenderRuleKind,
} from '@kutup/mail-core/senderRules'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Input } from '@kutup/ui/components/input'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'

const KINDS: SenderRuleKind[] = ['spam', 'block', 'allow']
const ICON: Record<SenderRuleKind, ReactNode> = {
  spam: <OctagonAlert className="size-4 text-status-warn" aria-hidden />,
  block: <Ban className="size-4 text-destructive" aria-hidden />,
  allow: <ShieldCheck className="size-4 text-status-ok" aria-hidden />,
}

/**
 * Settings → Block and allow (Proton's `SpamFiltersSection`): addresses and
 * domains sent to Spam, blocked, or always allowed; filtered by list,
 * moved between lists, removed.
 */
export function SendersSettingsPage() {
  const { t } = useTranslation()
  const rules = useSenderRules()
  const set = useSetSenderRules()
  const update = useUpdateSenderRule()
  const remove = useDeleteSenderRules()
  const [tab, setTab] = useState<SenderRuleKind | 'all'>('all')
  const [pattern, setPattern] = useState('')
  const [kind, setKind] = useState<SenderRuleKind>('block')
  const [error, setError] = useState<string | undefined>()
  const failed = (e: unknown) => toast.error(apiErrorMessage(e, t('common.tryAgain')))

  if (rules.isPending) return <LoadingPanel label={t('common.loading')} />
  if (rules.isError) return <Alert variant="error">{apiErrorMessage(rules.error, t('common.tryAgain'))}</Alert>
  const shown = tab === 'all' ? rules.data : rules.data.filter((r) => r.kind === tab)

  function add() {
    const value = pattern.trim()
    if (!isSenderPattern(value)) {
      setError(t('senders.invalid'))
      return
    }
    set.mutate(
      { patterns: [value], kind },
      {
        onSuccess: () => {
          setPattern('')
          setError(undefined)
          toast.success(t(`senders.added.${kind}`, { who: value.replace(/^@/, '').toLowerCase() }))
        },
        onError: failed,
      },
    )
  }

  return (
    <PageBody>
      <PageHeader title={t('senders.title')} description={t('senders.description')} />
      <ul className="space-y-1 text-sm text-muted-foreground">
        {KINDS.map((k) => (
          <li key={k} className="flex items-start gap-2">
            {ICON[k]}
            <span>
              <strong className="font-medium text-foreground">{t(`senders.kinds.${k}`)}:</strong> {t(`senders.help.${k}`)}
            </span>
          </li>
        ))}
      </ul>
      <form
        className="mt-4 flex flex-wrap items-start gap-2"
        onSubmit={(e) => {
          e.preventDefault()
          add()
        }}
      >
        <div className="min-w-60 flex-1">
          <Input
            value={pattern}
            onChange={(e) => {
              setPattern(e.target.value)
              setError(undefined)
            }}
            placeholder={t('senders.placeholder')}
            aria-label={t('senders.pattern')}
            aria-invalid={!!error}
          />
          {error ? <p className="mt-1 text-sm text-destructive">{error}</p> : null}
        </div>
        <Select value={kind} onValueChange={(v) => setKind(v as SenderRuleKind)}>
          <SelectTrigger className="w-36" aria-label={t('senders.list')}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {KINDS.map((k) => (
              <SelectItem key={k} value={k}>
                {t(`senders.kinds.${k}`)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button type="submit" disabled={set.isPending}>
          {t('senders.add')}
        </Button>
      </form>
      <div role="tablist" aria-label={t('senders.list')} className="mt-6 flex gap-1 border-b border-border">
        {(['all', ...KINDS] as const).map((k) => (
          <button
            key={k}
            type="button"
            role="tab"
            aria-selected={tab === k}
            onClick={() => setTab(k)}
            className={cn(
              '-mb-px border-b-2 px-3 py-1.5 text-sm',
              tab === k ? 'border-primary font-medium' : 'border-transparent text-muted-foreground hover:text-foreground',
            )}
          >
            {k === 'all' ? t('senders.all') : t(`senders.kinds.${k}`)} ({k === 'all' ? rules.data.length : rules.data.filter((r) => r.kind === k).length})
          </button>
        ))}
      </div>
      {shown.length === 0 ? (
        <EmptyState title={t('senders.empty')} description={t('senders.emptyHint')} />
      ) : (
        <ul className="rounded-b-lg border border-t-0 border-border">
          {shown.map((rule) => (
            <li key={rule.id} className="flex items-center gap-3 border-b border-border px-3 py-2 last:border-b-0">
              {ICON[rule.kind]}
              <span className="min-w-0 flex-1 truncate text-sm">{rule.pattern}</span>
              <Select
                value={rule.kind}
                onValueChange={(v) => update.mutate({ id: rule.id, kind: v as SenderRuleKind }, { onError: failed })}
              >
                <SelectTrigger className="h-8 w-32" aria-label={t('senders.moveFor', { who: rule.pattern })}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {KINDS.map((k) => (
                    <SelectItem key={k} value={k}>
                      {t(`senders.kinds.${k}`)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Tooltip label={t('senders.remove')}>
                <Button
                  variant="ghost"
                  size="icon"
                  className="size-8"
                  aria-label={t('senders.removeFor', { who: rule.pattern })}
                  onClick={() =>
                    remove.mutate([rule.id], {
                      onSuccess: () => toast.success(t('senders.removed', { who: rule.pattern })),
                      onError: failed,
                    })
                  }
                >
                  <Trash2 />
                </Button>
              </Tooltip>
            </li>
          ))}
        </ul>
      )}
    </PageBody>
  )
}
