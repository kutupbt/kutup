import { fieldValue, type EntryView, type VaultView } from '../vault/types'

/** What the entry list is sorted by (docs/plans/pass-gaps-2.md P3). */
export type SortKey = 'title' | 'userName' | 'url' | 'modified' | 'created' | 'expiry'
export const SORT_KEYS: SortKey[] = ['title', 'userName', 'url', 'modified', 'created', 'expiry']
/** What a row can show besides its title. */
export type Column = 'userName' | 'url' | 'modified' | 'expiry' | 'attachments' | 'totp'
export const COLUMNS: Column[] = ['userName', 'url', 'modified', 'expiry', 'attachments', 'totp']

export interface ListPrefs {
  sort: SortKey
  descending: boolean
  columns: Column[]
}

/** As the list was before: by title, the user name (else URL) under it. */
export const DEFAULT_PREFS: ListPrefs = { sort: 'title', descending: false, columns: ['userName'] }
const STORAGE_KEY = 'kutup-pass-list'

/** This device's choice; the default when there is none or storage is off. */
export function loadPrefs(): ListPrefs {
  try {
    const raw = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? 'null') as Partial<ListPrefs> | null
    if (!raw) return DEFAULT_PREFS
    return {
      sort: SORT_KEYS.includes(raw.sort as SortKey) ? (raw.sort as SortKey) : DEFAULT_PREFS.sort,
      descending: raw.descending === true,
      columns: Array.isArray(raw.columns) ? COLUMNS.filter((c) => raw.columns!.includes(c)) : DEFAULT_PREFS.columns,
    }
  } catch {
    return DEFAULT_PREFS
  }
}

export function savePrefs(prefs: ListPrefs): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs))
  } catch {
    // Storage off (a private window): the choice lasts this page.
  }
}

export function hasTotp(entry: EntryView): boolean {
  return entry.fields.some((f) => f.key === 'otp' && f.value !== '')
}

const collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true })

/**
 * The entries in the chosen order. Text sorts as words do (case and accents
 * aside, numbers by value); times by when. Entries without the value go
 * last either way, then by title.
 */
export function sortEntries(entries: EntryView[], sort: SortKey, descending: boolean): EntryView[] {
  const value = (e: EntryView): string | null => {
    switch (sort) {
      case 'title':
        return fieldValue(e, 'Title') || null
      case 'userName':
        return fieldValue(e, 'UserName') || null
      case 'url':
        return fieldValue(e, 'URL') || null
      case 'modified':
        return e.modified
      case 'created':
        return e.created
      case 'expiry':
        return e.expires ? e.expiry : null
    }
  }
  const byTitle = (a: EntryView, b: EntryView) => collator.compare(fieldValue(a, 'Title'), fieldValue(b, 'Title'))
  const isTime = sort === 'modified' || sort === 'created' || sort === 'expiry'
  return [...entries].sort((a, b) => {
    const [x, y] = [value(a), value(b)]
    if (x === null || y === null) return x === y ? byTitle(a, b) : x === null ? 1 : -1
    const order = isTime ? (x < y ? -1 : x > y ? 1 : 0) : collator.compare(x, y)
    return (descending ? -order : order) || byTitle(a, b)
  })
}

/** The vault's tags outside the recycle bin, with how many entries carry each, A to Z. */
export function vaultTags(view: Pick<VaultView, 'entries'>): { tag: string; count: number }[] {
  const counts = new Map<string, number>()
  for (const entry of view.entries) {
    if (entry.inRecycleBin) continue
    for (const tag of new Set(entry.tags)) counts.set(tag, (counts.get(tag) ?? 0) + 1)
  }
  return [...counts].map(([tag, count]) => ({ tag, count })).sort((a, b) => collator.compare(a.tag, b.tag))
}

/** The search that shows one tag's entries. */
export function tagQuery(tag: string): string {
  return `tag:"${tag.replaceAll('"', '')}"`
}
