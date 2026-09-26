import { Lock, MapPinned } from 'lucide-react'
import { lazy, Suspense } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useMapConfig, useSaveMapPreferences, usesRelay, type MapConfig, type MapPreferences } from '@kutup/map/config'
import { Alert } from '@kutup/ui/components/alert'
import { Card, CardContent } from '@kutup/ui/components/card'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Label } from '@kutup/ui/components/label'
import { PageBody, PageHeader, Section } from '@kutup/ui/components/page'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'

// MapLibre is large: load it only when a map is shown.
const MapView = lazy(() => import('@kutup/map/MapView').then((m) => ({ default: m.MapView })))

/** Where the preview map opens. */
const PREVIEW = { lat: 41.0082, lon: 28.9784 }

/**
 * Your map choices (docs/plans/maps.md): maps stay off until you turn them
 * on, and you choose among the providers this server offers, loaded
 * directly or through the server.
 */
export function MapsPage() {
  const { t } = useTranslation()
  const config = useMapConfig()
  const save = useSaveMapPreferences()

  function update(next: Partial<MapPreferences>, current: MapConfig) {
    save.mutate(
      { ...current.preferences, ...next },
      {
        onSuccess: () => toast.success(t('settings.maps.saved')),
        onError: (error) => toast.error(apiErrorMessage(error, t('settings.maps.saveFailed'))),
      },
    )
  }

  return (
    <PageBody width="prose">
      <PageHeader title={t('settings.maps.title')} description={t('settings.maps.description')} />
      {config.isPending ? (
        <Skeleton className="h-48 w-full" />
      ) : config.isError ? (
        <Alert variant="error">{apiErrorMessage(config.error, t('common.tryAgain'))}</Alert>
      ) : !config.data.enabled || config.data.providers.length === 0 ? (
        <Alert>{t('settings.maps.offByServer')}</Alert>
      ) : (
        <Choices config={config.data} onChange={(next) => update(next, config.data)} busy={save.isPending} />
      )}
    </PageBody>
  )
}

function Choices({ config, onChange, busy }: { config: MapConfig; onChange: (next: Partial<MapPreferences>) => void; busy: boolean }) {
  const { t } = useTranslation()
  const { preferences } = config
  const provider = config.providers.find((p) => p.id === preferences.provider) ?? config.providers[0]
  const relayed = usesRelay(config.proxy, preferences.viaProxy)

  return (
    <div className="space-y-6">
      <Section title={t('settings.maps.show')}>
        <Card>
          <CardContent className="space-y-4 p-5">
            <div className="flex items-start gap-3">
              <Checkbox
                id="maps-enabled"
                checked={preferences.enabled}
                disabled={busy}
                onCheckedChange={(value) => onChange({ enabled: value === true, provider: provider.id })}
                data-testid="maps-enabled"
              />
              <div className="space-y-1">
                <Label htmlFor="maps-enabled">{t('settings.maps.enable')}</Label>
                <p className="text-sm text-muted-foreground">{t('settings.maps.enableHint')}</p>
              </div>
            </div>
            <div data-testid="maps-notice">
            <Alert>
              <p>
                {relayed
                  ? t('settings.maps.noticeRelay', { provider: provider.name })
                  : t('settings.maps.noticeDirect', { provider: provider.name })}
              </p>
              <p className="mt-2 flex items-start gap-2">
                <Lock className="mt-0.5 size-4 shrink-0" aria-hidden />
                {t('settings.maps.noticeEncrypted')}
              </p>
            </Alert>
            </div>
          </CardContent>
        </Card>
      </Section>

      <Section title={t('settings.maps.provider')} description={t('settings.maps.providerHint')}>
        <Card>
          <CardContent className="space-y-4 p-5">
            <Select value={provider.id} onValueChange={(id) => onChange({ provider: id as MapPreferences['provider'] })} disabled={busy}>
              <SelectTrigger aria-label={t('settings.maps.provider')} data-testid="maps-provider">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {config.providers.map((p) => (
                  <SelectItem key={p.id} value={p.id}>
                    {p.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {config.proxy === 'available' ? (
              <div className="flex items-start gap-3">
                <Checkbox
                  id="maps-relay"
                  checked={preferences.viaProxy}
                  disabled={busy}
                  onCheckedChange={(value) => onChange({ viaProxy: value === true })}
                  data-testid="maps-relay"
                />
                <div className="space-y-1">
                  <Label htmlFor="maps-relay">{t('settings.maps.relay')}</Label>
                  <p className="text-sm text-muted-foreground">{t('settings.maps.relayHint')}</p>
                </div>
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">
                {config.proxy === 'enforced' ? t('settings.maps.relayEnforced') : t('settings.maps.relayOff')}
              </p>
            )}
          </CardContent>
        </Card>
      </Section>

      {preferences.enabled ? (
        <Section title={t('settings.maps.preview')}>
          <Suspense fallback={<Skeleton className="h-72 w-full" />}>
            <MapView
              key={`${provider.id}:${relayed}`}
              center={PREVIEW}
              zoom={11}
              className="h-72 w-full overflow-hidden rounded-lg border border-border"
              ariaLabel={t('settings.maps.preview')}
            />
          </Suspense>
        </Section>
      ) : (
        <p className="flex items-center gap-2 text-sm text-muted-foreground">
          <MapPinned className="size-4" aria-hidden />
          {t('settings.maps.offForYou')}
        </p>
      )}
    </div>
  )
}
