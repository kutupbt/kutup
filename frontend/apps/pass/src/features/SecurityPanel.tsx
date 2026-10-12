import { CalendarX, Copy, ShieldAlert, ShieldCheck } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Badge } from '@kutup/ui/components/badge'
import { securityReport } from '../lib/report'
import { fieldValue, type EntryView, type VaultView } from '../vault/types'

function EntryLink({ entry, onOpen }: { entry: EntryView; onOpen: (id: string) => void }) {
  const { t } = useTranslation()
  return (
    <li>
      <button type="button" onClick={() => onOpen(entry.id)} className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-left hover:bg-accent/50">
        <span className="grid size-7 shrink-0 place-items-center rounded-md bg-muted text-xs font-semibold uppercase">
          {(fieldValue(entry, 'Title') || '?').slice(0, 1)}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm font-medium">{fieldValue(entry, 'Title') || t('entry.untitled')}</span>
          <span className="block truncate text-xs text-muted-foreground">{fieldValue(entry, 'UserName') || fieldValue(entry, 'URL')}</span>
        </span>
      </button>
    </li>
  )
}

function Section({ title, description, count, icon, children }: { title: string; description: string; count: number; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-border" aria-label={title}>
      <header className="flex items-start gap-3 border-b border-border p-4">
        <span className="mt-0.5 text-muted-foreground">{icon}</span>
        <div className="min-w-0 flex-1">
          <h3 className="font-medium">{title}</h3>
          <p className="text-xs text-muted-foreground">{description}</p>
        </div>
        <Badge variant={count > 0 ? 'warn' : 'ok'}>{count}</Badge>
      </header>
      {count > 0 ? <div className="p-2">{children}</div> : null}
    </section>
  )
}

/** Weak, reused and expired passwords in the vault, worked out on this device. */
export function SecurityPanel({ view, onOpen }: { view: VaultView; onOpen: (id: string) => void }) {
  const { t } = useTranslation()
  const report = securityReport(view)
  const issues = report.weak.length + report.reused.reduce((n, g) => n + g.length, 0) + report.expired.length
  return (
    <div className="h-full overflow-y-auto p-4 md:p-6">
      <div className="mx-auto max-w-3xl space-y-4">
        <div className="flex items-start gap-3">
          {issues === 0 ? <ShieldCheck className="size-6 text-status-ok" aria-hidden /> : <ShieldAlert className="size-6 text-status-warn" aria-hidden />}
          <div>
            <h2 className="font-display text-lg font-semibold tracking-tight">{t('report.title')}</h2>
            <p className="text-sm text-muted-foreground">
              {issues === 0 ? t('report.allGood', { count: report.checked }) : t('report.summary', { count: report.checked })}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">{t('report.private')}</p>
          </div>
        </div>
        <Section title={t('report.weak')} description={t('report.weakDescription')} count={report.weak.length} icon={<ShieldAlert className="size-5" />}>
          <ul>
            {report.weak.map((e) => (
              <EntryLink key={e.id} entry={e} onOpen={onOpen} />
            ))}
          </ul>
        </Section>
        <Section
          title={t('report.reused')}
          description={t('report.reusedDescription')}
          count={report.reused.reduce((n, g) => n + g.length, 0)}
          icon={<Copy className="size-5" />}
        >
          <div className="space-y-3">
            {report.reused.map((group, index) => (
              <div key={index}>
                <p className="px-3 pt-1 text-xs text-muted-foreground">{t('report.sharedBy', { count: group.length })}</p>
                <ul>
                  {group.map((e) => (
                    <EntryLink key={e.id} entry={e} onOpen={onOpen} />
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </Section>
        <Section title={t('report.expired')} description={t('report.expiredDescription')} count={report.expired.length} icon={<CalendarX className="size-5" />}>
          <ul>
            {report.expired.map((e) => (
              <EntryLink key={e.id} entry={e} onOpen={onOpen} />
            ))}
          </ul>
        </Section>
      </div>
    </div>
  )
}
