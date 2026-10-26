import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { Card } from '@kutup/ui/components/card'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Mono } from '@kutup/ui/components/mono'
import { Section } from '@kutup/ui/components/page'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { formatInstant } from '@kutup/ui/lib/format'
import { useDevices, useRevokeDevice, type EditorDevice } from './api'

/**
 * Editing devices and CLIs: each editing app of each browser (Drive,
 * Office, Maps, Pass, and this page once it has removed a device) and each
 * CLI is a device of the account, with its own key that signs its
 * collaborative edits, listed in the account's signed device list
 * (docs/plans/one-device-list.md). Removing one publishes the list without
 * it: its edits stop being accepted and its live editing connections close.
 */
export function EditorKeysSection() {
  const { t, i18n } = useTranslation()
  const devices = useDevices()
  const revoke = useRevokeDevice()
  const [revoking, setRevoking] = useState<EditorDevice | null>(null)
  // This sign-in's first, then the rest; newest first within each.
  const rows = devices.data
    ? [...devices.data].sort(
        (a, b) => Number(b.thisSignIn) - Number(a.thisSignIn) || b.createdAt.localeCompare(a.createdAt),
      )
    : []

  return (
    <Section title={t('settings.devices.title')} description={t('settings.devices.description')}>
      {devices.isError ? (
        <Alert variant="error">{apiErrorMessage(devices.error, t('common.tryAgain'))}</Alert>
      ) : null}
      {devices.isPending ? <LoadingPanel label={t('common.loading')} /> : null}
      {devices.data && rows.length === 0 ? (
        <EmptyState title={t('settings.devices.emptyTitle')} description={t('settings.devices.emptyDescription')} />
      ) : null}
      {rows.length > 0 ? (
        <Card className="divide-y divide-border p-0">
          {rows.map((d) => (
            <div key={d.deviceId} className="flex flex-wrap items-center gap-4 p-4" data-testid="account-editor-device">
              <div className="min-w-0 flex-1 space-y-1">
                <p className="flex flex-wrap items-center gap-2 font-medium">
                  <span className="min-w-0 break-words">{d.name || t('settings.devices.unnamed')}</span>
                  <Mono className="text-xs text-muted-foreground">#{d.deviceId}</Mono>
                  <Badge variant="neutral">
                    {d.kind === 'cli' ? t('settings.devices.kindCli') : t('settings.devices.kindEditor')}
                  </Badge>
                  {d.thisSignIn ? <Badge variant="neutral">{t('settings.devices.thisSignIn')}</Badge> : null}
                  {d.expired ? (
                    <Badge variant="neutral">{t('settings.devices.expired')}</Badge>
                  ) : !d.listed ? (
                    <Badge variant="neutral">{t('settings.devices.notListed')}</Badge>
                  ) : null}
                </p>
                <p className="text-xs text-muted-foreground">
                  {t('settings.devices.added', { when: formatInstant(d.createdAt, i18n.language) })}
                  {' · '}
                  {d.lastSeenAt
                    ? t('settings.devices.lastSeen', { when: formatInstant(d.lastSeenAt, i18n.language) })
                    : t('settings.devices.neverSeen')}
                </p>
              </div>
              <Button variant="outline" size="sm" onClick={() => setRevoking(d)}>
                {t('settings.devices.revoke')}
              </Button>
            </div>
          ))}
        </Card>
      ) : null}
      <ConfirmDestructive
        open={revoking !== null}
        onOpenChange={(open) => {
          if (!open) {
            setRevoking(null)
            revoke.reset()
          }
        }}
        title={t('settings.devices.revokeTitle')}
        description={t('settings.devices.revokeDescription', {
          name: revoking?.name || t('settings.devices.unnamed'),
        })}
        submit={t('settings.devices.revoke')}
        pending={revoke.isPending}
        error={revoke.error}
        errorFallback={t('settings.devices.revokeFailed')}
        onConfirm={() => {
          if (!revoking) return
          revoke.mutate(revoking, {
            onSuccess: () => {
              toast.success(t('settings.devices.revokedToast'))
              setRevoking(null)
            },
          })
        }}
      />
    </Section>
  )
}
