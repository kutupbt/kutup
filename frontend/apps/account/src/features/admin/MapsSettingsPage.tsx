import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { mapConfigKey, type CustomProvider, type MapSettings, type ProviderId, type ProxyMode, type TileKind } from '@kutup/map/config'
import api from '@kutup/session/client'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Card, CardContent } from '@kutup/ui/components/card'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { PageBody, PageHeader, Section } from '@kutup/ui/components/page'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { adminKey } from './api'
import { Choice } from './federation/Choice'

const mapsKey = [...adminKey, 'maps'] as const
const BUILT_IN: ProviderId[] = ['openfreemap', 'openstreetmap']
const PROXY_MODES: readonly ProxyMode[] = ['off', 'available', 'enforced']
const KINDS: readonly TileKind[] = ['vector', 'raster']
const EMPTY_CUSTOM: CustomProvider = { name: '', kind: 'vector', url: '', attribution: '' }
const OSM_POLICY = 'https://operations.osmfoundation.org/policies/tiles/'

/**
 * The server's map settings (docs/plans/maps.md): which providers people may
 * choose, the server's own tile server, whether map traffic may or must go
 * through this server, and the size of its shared tile cache.
 */
export function MapsSettingsPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const settings = useQuery({
    queryKey: mapsKey,
    queryFn: async () => (await api.get<MapSettings>('/admin/maps')).data,
  })
  const save = useMutation({
    mutationFn: async (next: MapSettings) => (await api.put<MapSettings>('/admin/maps', next)).data,
    onSuccess: async (saved) => {
      queryClient.setQueryData(mapsKey, saved)
      await queryClient.invalidateQueries({ queryKey: mapConfigKey })
      await queryClient.invalidateQueries({ queryKey: adminKey })
      toast.success(t('admin.maps.saved'))
    },
  })
  const [draft, setDraft] = useState<MapSettings | null>(null)
  useEffect(() => {
    if (settings.data) setDraft(settings.data)
  }, [settings.data])

  if (settings.isPending || !draft) {
    return settings.isError ? (
      <PageBody width="prose"><Alert variant="error">{apiErrorMessage(settings.error, t('common.tryAgain'))}</Alert></PageBody>
    ) : (
      <LoadingPanel label={t('common.loading')} />
    )
  }

  const offersCustom = draft.providers.includes('custom')
  const custom = draft.custom ?? EMPTY_CUSTOM
  const changed = JSON.stringify(draft) !== JSON.stringify(settings.data)

  function toggleProvider(id: ProviderId, on: boolean) {
    setDraft((d) => {
      if (!d) return d
      const providers = on ? [...d.providers.filter((p) => p !== id), id] : d.providers.filter((p) => p !== id)
      return { ...d, providers, custom: id === 'custom' ? (on ? (d.custom ?? EMPTY_CUSTOM) : null) : d.custom }
    })
  }
  const setCustom = (patch: Partial<CustomProvider>) =>
    setDraft((d) => (d ? { ...d, custom: { ...(d.custom ?? EMPTY_CUSTOM), ...patch } } : d))

  return (
    <PageBody width="prose">
      <PageHeader title={t('admin.maps.title')} description={t('admin.maps.description')} />
      <form
        className="space-y-6"
        noValidate
        onSubmit={(event) => {
          event.preventDefault()
          save.mutate(draft)
        }}
      >
        <Section title={t('admin.maps.availability')}>
          <Card>
            <CardContent className="flex items-start gap-3 p-5">
              <Checkbox
                id="maps-server-enabled"
                checked={draft.enabled}
                onCheckedChange={(v) => setDraft({ ...draft, enabled: v === true })}
                data-testid="admin-maps-enabled"
              />
              <div className="space-y-1">
                <Label htmlFor="maps-server-enabled">{t('admin.maps.enabled')}</Label>
                <p className="text-sm text-muted-foreground">{t('admin.maps.enabledHint')}</p>
              </div>
            </CardContent>
          </Card>
        </Section>

        <Section title={t('admin.maps.providers')} description={t('admin.maps.providersHint')}>
          <Card>
            <CardContent className="space-y-4 p-5">
              {[...BUILT_IN, 'custom' as const].map((id) => (
                <div key={id} className="flex items-start gap-3">
                  <Checkbox
                    id={`maps-provider-${id}`}
                    checked={draft.providers.includes(id)}
                    disabled={!draft.enabled}
                    onCheckedChange={(v) => toggleProvider(id, v === true)}
                    data-testid={`admin-maps-provider-${id}`}
                  />
                  <div className="space-y-1">
                    <Label htmlFor={`maps-provider-${id}`}>{t(`admin.maps.provider.${id}`)}</Label>
                    <p className="text-sm text-muted-foreground">{t(`admin.maps.providerHint.${id}`)}</p>
                  </div>
                </div>
              ))}
              {offersCustom ? (
                <div className="grid gap-4 border-t border-border pt-4 sm:grid-cols-2">
                  <Field label={t('admin.maps.customName')} required>
                    {(field) => <Input {...field} value={custom.name} maxLength={60} onChange={(e) => setCustom({ name: e.target.value })} />}
                  </Field>
                  <Field label={t('admin.maps.customKind')}>
                    {() => (
                      <Choice value={custom.kind} options={KINDS} labelPrefix="admin.maps.kind" ariaLabel={t('admin.maps.customKind')} onChange={(kind) => setCustom({ kind })} />
                    )}
                  </Field>
                  <Field
                    label={t('admin.maps.customUrl')}
                    description={custom.kind === 'vector' ? t('admin.maps.customUrlVector') : t('admin.maps.customUrlRaster')}
                    className="sm:col-span-2"
                    required
                  >
                    {(field) => <Input {...field} value={custom.url} maxLength={500} inputMode="url" onChange={(e) => setCustom({ url: e.target.value })} />}
                  </Field>
                  <Field label={t('admin.maps.customAttribution')} className="sm:col-span-2">
                    {(field) => <Input {...field} value={custom.attribution} maxLength={200} onChange={(e) => setCustom({ attribution: e.target.value })} />}
                  </Field>
                </div>
              ) : null}
            </CardContent>
          </Card>
        </Section>

        <Section title={t('admin.maps.relay')} description={t('admin.maps.relayHint')}>
          <Card>
            <CardContent className="grid gap-4 p-5 sm:grid-cols-2">
              <Field label={t('admin.maps.relayMode')} description={t(`admin.maps.proxyHint.${draft.proxy}`)}>
                {() => (
                  <Choice
                    value={draft.proxy}
                    options={PROXY_MODES}
                    labelPrefix="admin.maps.proxy"
                    ariaLabel={t('admin.maps.relayMode')}
                    onChange={(proxy) => setDraft({ ...draft, proxy })}
                    disabled={!draft.enabled}
                  />
                )}
              </Field>
              <Field label={t('admin.maps.cache')} description={t('admin.maps.cacheHint')}>
                {(field) => (
                  <Input
                    {...field}
                    type="number"
                    min={0}
                    max={102400}
                    step={1}
                    inputMode="numeric"
                    value={draft.cacheMegabytes}
                    disabled={draft.proxy === 'off'}
                    onChange={(e) => setDraft({ ...draft, cacheMegabytes: Math.max(0, Math.floor(Number(e.target.value) || 0)) })}
                    data-testid="admin-maps-cache"
                  />
                )}
              </Field>
              {draft.proxy !== 'off' && draft.cacheMegabytes === 0 && draft.providers.includes('openstreetmap') ? (
                <Alert variant="warn" className="sm:col-span-2">
                  {t('admin.maps.noCacheWarning')}{' '}
                  <a href={OSM_POLICY} target="_blank" rel="noreferrer" className="underline">{t('admin.maps.osmPolicy')}</a>
                </Alert>
              ) : null}
            </CardContent>
          </Card>
        </Section>

        {save.isError ? <Alert variant="error">{apiErrorMessage(save.error, t('admin.maps.saveFailed'))}</Alert> : null}
        <div className="flex justify-end">
          <Button type="submit" loading={save.isPending} disabled={!changed} data-testid="admin-maps-save">{t('common.save')}</Button>
        </div>
      </form>
    </PageBody>
  )
}
