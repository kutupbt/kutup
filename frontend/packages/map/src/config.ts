import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import api from '@kutup/session/client'

// Maps (docs/plans/maps.md). The administrator chooses which providers are
// offered and whether tiles may, or must, go through this server's relay;
// each person turns maps on (off by default) and chooses within that.

export type ProviderId = 'openfreemap' | 'openstreetmap' | 'custom'
export type TileKind = 'vector' | 'raster'
export type ProxyMode = 'off' | 'available' | 'enforced'

export interface MapProvider {
  id: ProviderId
  name: string
  kind: TileKind
  /** Style URL (vector) or `{z}/{x}/{y}` template (raster) at the provider. */
  url: string
  /** The same through the relay, a path on this origin; absent when the relay is off. */
  proxyUrl: string | null
  /**
   * Whether browsers may load it from the provider itself: its origin is in
   * the server's KUTUP_MAP_DIRECT_ORIGINS, which the apps' Content-Security-
   * Policy allows (docs/content-security-policy.md). Otherwise only the relay.
   */
  direct: boolean
  attribution: string
}

export interface MapPreferences {
  enabled: boolean
  provider: ProviderId | null
  viaProxy: boolean
  /** Where the Maps app puts new lists: one of your own folders; null is My files. */
  saveFolderId: string | null
}

export interface MapConfig {
  /** False: the administrator turned maps off. */
  enabled: boolean
  proxy: ProxyMode
  providers: MapProvider[]
  preferences: MapPreferences
}

export interface CustomProvider {
  name: string
  kind: TileKind
  url: string
  attribution: string
}

/** The administrator's settings (`PUT /api/v1/admin/maps`). */
export interface MapSettings {
  enabled: boolean
  providers: ProviderId[]
  custom: CustomProvider | null
  proxy: ProxyMode
  cacheMegabytes: number
}

/** The settings as `GET /api/v1/admin/maps` answers: with what the server was started with. */
export interface AdminMapSettings extends MapSettings {
  /** KUTUP_MAP_DIRECT_ORIGINS: the providers' origins browsers may load from directly. */
  directOrigins: string[]
}

/** The built-in providers' origins (the server's `maps::Upstream`). */
export const BUILT_IN_ORIGINS: Record<Exclude<ProviderId, 'custom'>, string> = {
  openfreemap: 'https://tiles.openfreemap.org',
  openstreetmap: 'https://tile.openstreetmap.org',
}

/** A provider's origin under `settings`, or null when it has none yet (a custom one without a valid address). */
export function providerOrigin(id: ProviderId, custom: CustomProvider | null): string | null {
  if (id !== 'custom') return BUILT_IN_ORIGINS[id]
  try {
    return custom ? new URL(custom.url).origin : null
  } catch {
    return null
  }
}

/** What a map on this device should load, or null when maps are off. */
export interface EffectiveMap {
  provider: MapProvider
  viaProxy: boolean
  /** Absolute style URL or tile template. */
  url: string
}

export const mapConfigKey = ['map-config'] as const

export function useMapConfig() {
  return useQuery({
    queryKey: mapConfigKey,
    queryFn: async () => (await api.get<MapConfig>('/maps')).data,
    staleTime: 5 * 60_000,
  })
}

export function useSaveMapPreferences() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (preferences: MapPreferences) =>
      (await api.put<MapConfig>('/maps/preferences', preferences)).data,
    onSuccess: (config) => queryClient.setQueryData(mapConfigKey, config),
  })
}

/**
 * Whether tiles go through the relay: always for a provider browsers may not
 * load directly; otherwise by the administrator's mode and the person's choice.
 */
export function usesRelay(proxy: ProxyMode, viaProxy: boolean, provider: Pick<MapProvider, 'direct' | 'proxyUrl'>): boolean {
  if (provider.proxyUrl === null) return false
  return !provider.direct || proxy === 'enforced' || (proxy === 'available' && viaProxy)
}

/**
 * The map this person sees: nothing when the administrator or the person
 * turned maps off; otherwise their provider (or the first offered), direct
 * or through the relay.
 */
export function effectiveMap(config: MapConfig | undefined, origin = window.location.origin): EffectiveMap | null {
  if (!config?.enabled || !config.preferences.enabled || config.providers.length === 0) return null
  const provider =
    config.providers.find((p) => p.id === config.preferences.provider) ?? config.providers[0]
  const viaProxy = usesRelay(config.proxy, config.preferences.viaProxy, provider)
  const url = viaProxy ? origin + provider.proxyUrl : provider.url
  return { provider, viaProxy, url }
}

export function useEffectiveMap(): EffectiveMap | null {
  return effectiveMap(useMapConfig().data)
}
