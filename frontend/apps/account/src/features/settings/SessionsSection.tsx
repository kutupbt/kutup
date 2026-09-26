import { LogOut, Monitor, Terminal } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { Card } from '@kutup/ui/components/card'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Section } from '@kutup/ui/components/page'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { formatInstant, formatRelative } from '@kutup/ui/lib/format'
import { useRevokeOtherSessions, useRevokeSession, useSessions, type SessionView } from './api'
import { describeUserAgent } from './userAgent'

/** One sign-in: a root session (account. or a CLI) and the app sessions forked from it. */
interface SignIn {
  root: SessionView
  apps: SessionView[]
  lastUsedAt: string
  current: boolean
}

function groupSignIns(sessions: SessionView[]): SignIn[] {
  const byRoot = new Map<string, SessionView[]>()
  for (const s of sessions) {
    const root = s.parentId ?? s.id
    byRoot.set(root, [...(byRoot.get(root) ?? []), s])
  }
  const groups: SignIn[] = []
  for (const [rootId, members] of byRoot) {
    // A child whose parent already ended is its own group.
    const root = members.find((m) => m.id === rootId) ?? members[0]
    const lastUsedAt = members.map((m) => m.lastUsedAt).sort().at(-1) ?? root.lastUsedAt
    groups.push({ root, apps: members, lastUsedAt, current: members.some((m) => m.current) })
  }
  return groups.sort((a, b) => Number(b.current) - Number(a.current) || b.lastUsedAt.localeCompare(a.lastUsedAt))
}

const CLIENT_KEYS: Record<string, string> = {
  'web-account': 'apps.account',
  'web-drive': 'apps.drive',
  'web-chat': 'apps.chat',
  'web-maps': 'apps.maps',
  cli: 'settings.sessions.cli',
}

export function SessionsSection() {
  const { t, i18n } = useTranslation()
  const sessions = useSessions()
  const revoke = useRevokeSession()
  const revokeOthers = useRevokeOtherSessions()
  const [ending, setEnding] = useState<SignIn | null>(null)
  const [endingOthers, setEndingOthers] = useState(false)

  const groups = sessions.data ? groupSignIns(sessions.data) : []
  const others = groups.filter((g) => !g.current)

  return (
    <Section
      title={t('settings.sessions.title')}
      description={t('settings.sessions.description')}
      actions={
        others.length > 0 ? (
          <Button variant="outline" onClick={() => setEndingOthers(true)}>
            <LogOut />
            {t('settings.sessions.endOthers')}
          </Button>
        ) : null
      }
    >
      {sessions.isError ? (
        <Alert variant="error">{apiErrorMessage(sessions.error, t('common.tryAgain'))}</Alert>
      ) : null}
      {sessions.isPending ? <LoadingPanel label={t('common.loading')} /> : null}
      {sessions.data && groups.length === 0 ? (
        <EmptyState title={t('settings.sessions.emptyTitle')} description={t('settings.sessions.emptyDescription')} />
      ) : null}

      {groups.length > 0 ? (
        <Card className="divide-y divide-border p-0">
          {groups.map((group) => {
            const cli = group.root.clientType === 'cli'
            const { browser, os } = describeUserAgent(group.root.userAgent)
            const name = cli
              ? t('settings.sessions.cli')
              : browser && os
                ? t('settings.sessions.browserOn', { browser, os })
                : (browser ?? os ?? t('settings.sessions.unknownBrowser'))
            return (
              <div key={group.root.id} className="flex flex-wrap items-center gap-4 p-4">
                <span className="flex size-10 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground [&_svg]:size-5">
                  {cli ? <Terminal /> : <Monitor />}
                </span>
                <div className="min-w-0 flex-1 space-y-1">
                  <p className="flex flex-wrap items-center gap-2 font-medium">
                    {name}
                    {group.current ? <Badge variant="ok">{t('settings.sessions.thisDevice')}</Badge> : null}
                  </p>
                  {!cli ? (
                    <p className="text-sm text-muted-foreground">
                      {group.apps
                        .map((s) => t(CLIENT_KEYS[s.clientType] ?? 'settings.sessions.unknownApp'))
                        .join(' · ')}
                    </p>
                  ) : null}
                  <p className="text-xs text-muted-foreground">
                    <Tooltip label={formatInstant(group.lastUsedAt, i18n.language) ?? ''}>
                      <span>
                        {t('settings.sessions.lastActive', {
                          when: formatRelative(group.lastUsedAt, i18n.language),
                        })}
                      </span>
                    </Tooltip>
                    {' · '}
                    {t('settings.sessions.signedIn', { when: formatInstant(group.root.createdAt, i18n.language) })}
                  </p>
                </div>
                {!group.current ? (
                  <Button variant="outline" size="sm" onClick={() => setEnding(group)}>
                    {t('settings.sessions.end')}
                  </Button>
                ) : null}
              </div>
            )
          })}
        </Card>
      ) : null}

      <ConfirmDestructive
        open={ending !== null}
        onOpenChange={(open) => {
          if (!open) {
            setEnding(null)
            revoke.reset()
          }
        }}
        title={t('settings.sessions.endTitle')}
        description={t('settings.sessions.endDescription')}
        submit={t('settings.sessions.end')}
        pending={revoke.isPending}
        error={revoke.error}
        errorFallback={t('settings.sessions.endFailed')}
        onConfirm={() => {
          if (!ending) return
          revoke.mutate(ending.root.id, {
            onSuccess: () => {
              toast.success(t('settings.sessions.ended'))
              setEnding(null)
            },
          })
        }}
      />
      <ConfirmDestructive
        open={endingOthers}
        onOpenChange={(open) => {
          if (!open) {
            setEndingOthers(false)
            revokeOthers.reset()
          }
        }}
        title={t('settings.sessions.endOthersTitle')}
        description={t('settings.sessions.endOthersDescription', { count: others.length })}
        submit={t('settings.sessions.endOthers')}
        pending={revokeOthers.isPending}
        error={revokeOthers.error}
        errorFallback={t('settings.sessions.endFailed')}
        onConfirm={() => {
          revokeOthers.mutate(undefined, {
            onSuccess: () => {
              toast.success(t('settings.sessions.endedOthers'))
              setEndingOthers(false)
            },
          })
        }}
      />
    </Section>
  )
}
