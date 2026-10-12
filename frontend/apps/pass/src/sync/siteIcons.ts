// Website icons for entries (docs/plans/pass.md, "Site icons"), as Proton
// Pass's favicons. The account chooses, for every device, how they come:
// through Kutup (the server fetches them, so the website never sees this
// browser; the server sees the domain), straight from the website (the
// browser asks it for /favicon.ico, so it sees this browser's address), or
// not at all. Only the host name of an entry's address is ever sent.
// Icons are kept in this tab's memory, never on disk.

import { useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import api from '@kutup/session/client'

export type SiteIconsMode = 'kutup' | 'direct' | 'off'
export const SITE_ICON_MODES: readonly SiteIconsMode[] = ['kutup', 'direct', 'off']

const SETTINGS_KEY = ['pass', 'settings'] as const

interface PassSettings {
  siteIcons: SiteIconsMode
}

/** The account's choice; undefined (no icons yet) until it loads. */
export function useSiteIconsMode(): SiteIconsMode | undefined {
  return useQuery({
    queryKey: SETTINGS_KEY,
    queryFn: async () => (await api.get<PassSettings>('/pass/settings')).data,
    staleTime: 60_000,
    select: (settings) => settings.siteIcons,
  }).data
}

export function useSaveSiteIconsMode(): (mode: SiteIconsMode) => Promise<void> {
  const client = useQueryClient()
  return async (mode) => {
    await api.put('/pass/settings', { siteIcons: mode } satisfies PassSettings)
    client.setQueryData<PassSettings>(SETTINGS_KEY, { siteIcons: mode })
  }
}

/**
 * The host name whose icon an entry shows: from its URL field, with or
 * without a scheme; none for addresses that are not public names (IP
 * addresses, `localhost`, single labels), which have no icon to find.
 */
export function iconDomain(address: string): string | null {
  const value = address.trim()
  if (!value) return null
  // Another scheme without slashes (`mailto:`, `tel:`), not a host and port.
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value) && /^[a-z][a-z0-9+.-]*:(?!\d)/i.test(value)) return null
  let url: URL
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}`)
  } catch {
    return null
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null
  const host = url.hostname.toLowerCase().replace(/\.$/, '')
  if (!host.includes('.') || host.endsWith('.localhost') || host.startsWith('[') || /^[\d.]+$/.test(host)) return null
  return host
}

/** Fetches through Kutup, at most a few at a time; one try per domain per tab. */
const fetched = new Map<string, Promise<string | null>>()
const FETCHES_AT_ONCE = 6
let running = 0
const waiting: (() => void)[] = []

async function inTurn<T>(work: () => Promise<T>): Promise<T> {
  if (running >= FETCHES_AT_ONCE) await new Promise<void>((resolve) => waiting.push(resolve))
  running += 1
  try {
    return await work()
  } finally {
    running -= 1
    waiting.shift()?.()
  }
}

/** Thrown when the account's choice changed elsewhere: read it again. */
class NotKutupError extends Error {}

function throughKutup(domain: string): Promise<string | null> {
  let icon = fetched.get(domain)
  if (!icon) {
    icon = inTurn(async () => {
      try {
        const response = await api.post<Blob>('/pass/icon', { domain }, { responseType: 'blob' })
        return URL.createObjectURL(response.data)
      } catch (error) {
        if (isAxiosError(error) && error.response?.status === 403) throw new NotKutupError()
        // No icon, a refused name or a pause: the letter stays.
        return null
      }
    })
    fetched.set(domain, icon)
    // A refusal is not an answer about this domain.
    icon.catch(() => fetched.delete(domain))
  }
  return icon
}

/** The image address for an entry's icon, or null to show its letter. */
export function useSiteIcon(address: string): string | null {
  const mode = useSiteIconsMode()
  const client = useQueryClient()
  const domain = iconDomain(address)
  const [proxied, setProxied] = useState<{ domain: string; src: string | null } | null>(null)

  useEffect(() => {
    if (mode !== 'kutup' || !domain) return
    let current = true
    throughKutup(domain).then(
      (src) => current && setProxied({ domain, src }),
      () => void client.invalidateQueries({ queryKey: SETTINGS_KEY }),
    )
    return () => {
      current = false
    }
  }, [mode, domain, client])

  if (!domain) return null
  if (mode === 'direct') return `https://${domain}/favicon.ico`
  if (mode === 'kutup' && proxied?.domain === domain) return proxied.src
  return null
}
