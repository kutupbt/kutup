import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { Card } from '@kutup/ui/components/card'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Mono } from '@kutup/ui/components/mono'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { formatInstant } from '@kutup/ui/lib/format'
import { useDevices, useRevokeDevice, type EditorDevice } from './api'

/**
 * Editor devices: the per-browser Ed25519 keys that sign collaborative edits
 * (notes, office documents, whiteboards). Revoking one makes its signatures
 * stop being accepted and closes its live editing connections.
 */
export function DevicesPage() {
  const { t, i18n } = useTranslation()
  const devices = useDevices()
  const revoke = useRevokeDevice()
  const [revoking, setRevoking] = useState<EditorDevice | null>(null)
  const rows = devices.data ? [...devices.data].sort((a, b) => Number(b.isActive) - Number(a.isActive)) : []

  return (
    <PageBody width="prose">
      <PageHeader title={t('settings.devices.title')} description={t('settings.devices.description')} />
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
            <div key={d.deviceId} className="flex flex-wrap items-center gap-4 p-4">
              <div className="min-w-0 flex-1 space-y-1">
                <p className="flex flex-wrap items-center gap-2 font-medium">
                  {d.label || t('settings.devices.unnamed')}
                  <Mono className="text-xs text-muted-foreground">#{d.deviceId}</Mono>
                  {d.isActive ? null : <Badge variant="neutral">{t('settings.devices.revoked')}</Badge>}
                </p>
                <p className="text-xs text-muted-foreground">
                  {t('settings.devices.added', { when: formatInstant(d.createdAt, i18n.language) })}
                  {' · '}
                  {d.lastSeenAt
                    ? t('settings.devices.lastSeen', { when: formatInstant(d.lastSeenAt, i18n.language) })
                    : t('settings.devices.neverSeen')}
                </p>
              </div>
              {d.isActive ? (
                <Button variant="outline" size="sm" onClick={() => setRevoking(d)}>
                  {t('settings.devices.revoke')}
                </Button>
              ) : null}
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
          name: revoking?.label || t('settings.devices.unnamed'),
        })}
        submit={t('settings.devices.revoke')}
        pending={revoke.isPending}
        error={revoke.error}
        errorFallback={t('settings.devices.revokeFailed')}
        onConfirm={() => {
          if (!revoking) return
          revoke.mutate(revoking.deviceId, {
            onSuccess: () => {
              toast.success(t('settings.devices.revokedToast'))
              setRevoking(null)
            },
          })
        }}
      />
    </PageBody>
  )
}
