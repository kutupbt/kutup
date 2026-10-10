// Where each Kutup app lives.
//
// The origins are server configuration (KUTUP_ACCOUNT_URL, KUTUP_DRIVE_URL,
// KUTUP_CHAT_URL, KUTUP_MAPS_URL, KUTUP_PHOTOS_URL, KUTUP_OFFICE_URL, KUTUP_CONTACTS_URL, KUTUP_EDITOR_URL), published by `GET /api/auth/settings`,
// so a self-hoster can use any hostnames. The server enforces the same map
// for session forks; the client never derives an origin from a URL
// parameter.

import api from './client'

export type AppId = 'account' | 'drive' | 'chat' | 'maps' | 'photos' | 'office' | 'contacts'

export interface AppDirectory {
  account: string
  drive: string
  chat: string
  maps: string
  photos: string
  /** The Office home: documents, spreadsheets and presentations kept in Drive. */
  office: string
  /** The keyless OnlyOffice sandbox; embedded by drive, never navigated to. */
  editor: string
  /** The address book (docs/plans/contacts.md). */
  contacts: string
}

let directory: AppDirectory | null = null
let settings: Promise<Record<string, unknown>> | null = null

/**
 * The server's public settings (`GET /auth/settings`), fetched once per
 * page: the app origins, Chat's capabilities and the server's name all come
 * from it, and asking again costs a round trip on every start.
 */
export function loadServerSettings<T = Record<string, unknown>>(): Promise<T> {
  if (!settings) {
    settings = api.get<Record<string, unknown>>('/auth/settings').then((response) => response.data)
    settings.catch(() => {
      settings = null
    })
  }
  return settings as Promise<T>
}

function assertOrigin(value: unknown, name: string): string {
  if (typeof value !== 'string') throw new Error(`server did not publish the ${name} app origin`)
  const url = new URL(value)
  if (url.origin !== value.replace(/\/$/, '')) {
    throw new Error(`${name} app origin must be a bare origin, got ${value}`)
  }
  return url.origin
}

/** Load once at boot; every later `appUrl()` is synchronous. */
export async function loadAppDirectory(): Promise<AppDirectory> {
  if (directory) return directory
  const data = await loadServerSettings<{ apps?: Partial<Record<keyof AppDirectory, unknown>> }>()
  const apps = data.apps ?? {}
  directory = {
    account: assertOrigin(apps.account, 'account'),
    drive: assertOrigin(apps.drive, 'drive'),
    chat: assertOrigin(apps.chat, 'chat'),
    maps: assertOrigin(apps.maps, 'maps'),
    photos: assertOrigin(apps.photos, 'photos'),
    office: assertOrigin(apps.office, 'office'),
    editor: assertOrigin(apps.editor, 'editor'),
    contacts: assertOrigin(apps.contacts, 'contacts'),
  }
  return directory
}

export function getAppDirectory(): AppDirectory {
  if (!directory) throw new Error('getAppDirectory() before loadAppDirectory() settled')
  return directory
}

/** An absolute URL on another app, e.g. appUrl('account', '/settings/drive'). */
export function appUrl(app: keyof AppDirectory, path = '/'): string {
  return new URL(path, getAppDirectory()[app]).href
}

/** Test seam. */
export function setAppDirectoryForTesting(value: AppDirectory | null): void {
  directory = value
}
