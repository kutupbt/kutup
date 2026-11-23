import type { ObjectIdKey } from './accountRoots'
import { toBase64 } from './base64'
import type { MasterKeys } from './masterKeys'
import { getCryptoWasm } from './rustWasm'

// Records of the account-records store whose plaintext is JSON under the
// format-evolution rule (docs/plans/account-records.md, W3): contact groups
// and a calendar's own settings. Rust checks each plaintext (`v`, `min`,
// and fields a newer client added kept), seals it for its record id, and
// hashes plain ids into record ids under the account's object-id key.

/** The scopes whose records are JSON plaintexts. */
export type JsonRecordScope = 'contactGroups' | 'calendarSettings'

/** A contact group (`ContactGroupV1`). Spread an opened one to keep a newer client's fields. */
export interface ContactGroupRecord {
  v?: number
  name: string
  /** `#rrggbb`, lowercase. */
  color: string
  [field: string]: unknown
}

/** The account's own settings for one calendar (`CalendarSettingsV1`). */
export interface CalendarSettingsRecord {
  v?: number
  /** `#rrggbb`, lowercase. */
  color: string
  display: boolean
  /** The owner's roster of key recipients (keyed 8-character tags, concatenated; docs/plans/calendar-e3.md, "Roster"). */
  roster?: string
  [field: string]: unknown
}

/** The record id in `scope` of a plain id (a calendar's 16 UUID bytes, or 16 random bytes). */
export async function scopeRecordId(objectIdKey: ObjectIdKey, scope: JsonRecordScope, plainId: Uint8Array): Promise<string> {
  return (await getCryptoWasm()).scopeRecordId(objectIdKey, scope, toBase64(plainId))
}

/** Seals revision `revision` of record `id` of `scope`. */
export async function sealScopeRecord<T extends object>(
  masterKeys: MasterKeys,
  binding: string,
  scope: JsonRecordScope,
  id: string,
  revision: number,
  value: T,
): Promise<string> {
  return (await getCryptoWasm()).sealScopeRecord(masterKeys, binding, scope, id, revision, JSON.stringify({ v: 1, ...value }))
}

/** Opens record `id` of `scope`: its value and the revision it was sealed at. A newer client's record throws `newer format: …`. */
export async function openScopeRecord<T>(
  masterKeys: MasterKeys,
  binding: string,
  scope: JsonRecordScope,
  id: string,
  sealed: string,
): Promise<{ value: T; revision: number }> {
  const opened = (await getCryptoWasm()).openScopeRecord(masterKeys, binding, scope, id, sealed)
  return { value: JSON.parse(opened.value) as T, revision: opened.revision }
}
