// The vault's security report (docs/plans/pass.md, K2): weak, reused and
// expired passwords, worked out on the device from the open vault. Nothing
// leaves it: no password, hash or prefix is sent anywhere.

import { strengthOf } from './generator'
import { fieldValue, type EntryView, type VaultView } from '../vault/types'

export interface SecurityReport {
  /** Entries whose password is weak. */
  weak: EntryView[]
  /** Groups of entries that share one password (two or more each). */
  reused: EntryView[][]
  /** Entries past their expiry. */
  expired: EntryView[]
  /** How many entries have a password at all. */
  checked: number
}

export function securityReport(view: VaultView, now: Date = new Date()): SecurityReport {
  const live = view.entries.filter((e) => !e.inRecycleBin)
  const withPassword = live.filter((e) => fieldValue(e, 'Password') !== '')
  const byPassword = new Map<string, EntryView[]>()
  for (const entry of withPassword) {
    const password = fieldValue(entry, 'Password')
    byPassword.set(password, [...(byPassword.get(password) ?? []), entry])
  }
  const title = (e: EntryView) => fieldValue(e, 'Title')
  const byTitle = (a: EntryView, b: EntryView) => title(a).localeCompare(title(b), undefined, { sensitivity: 'base', numeric: true })
  return {
    weak: withPassword.filter((e) => strengthOf(fieldValue(e, 'Password')) === 'weak').sort(byTitle),
    reused: [...byPassword.values()]
      .filter((group) => group.length > 1)
      .map((group) => [...group].sort(byTitle))
      .sort((a, b) => b.length - a.length || byTitle(a[0], b[0])),
    expired: live.filter((e) => e.expires && e.expiry !== null && new Date(e.expiry) <= now).sort(byTitle),
    checked: withPassword.length,
  }
}
