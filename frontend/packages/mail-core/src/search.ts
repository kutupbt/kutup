// Advanced search (docs/plans/mail-parity.md, P6), as Proton's: a keyword,
// the sender, a recipient, a date range, which of your addresses, and "has
// attachments", kept in the address bar so a search can be reloaded,
// shared and gone back to. The place searched is the route itself.

export interface AdvancedSearch {
  /** Subjects and addresses contain this. */
  q: string
  /** The sender's address or name contains this. */
  from: string
  /** A recipient's (To, Cc, Bcc) address or name contains this. */
  to: string
  /** From this day on (YYYY-MM-DD, the reader's time zone). */
  since: string
  /** Up to and including this day. */
  until: string
  /** Came to or went from this address, or came through this list. */
  address: string
  attachments: boolean
}

export const EMPTY_SEARCH: AdvancedSearch = { q: '', from: '', to: '', since: '', until: '', address: '', attachments: false }

const TEXT_FIELDS = ['q', 'from', 'to', 'since', 'until', 'address'] as const
const DAY = /^\d{4}-\d{2}-\d{2}$/

/** The search in the address bar. */
export function searchFromParams(params: URLSearchParams): AdvancedSearch {
  const read = (name: string) => params.get(name)?.trim() ?? ''
  const day = (name: string) => (DAY.test(read(name)) ? read(name) : '')
  return {
    q: read('q'),
    from: read('from'),
    to: read('to'),
    since: day('since'),
    until: day('until'),
    address: read('address').toLowerCase(),
    attachments: params.get('filter') === 'attachments',
  }
}

/** The address bar's parameters for `search`: page and sort start again, as Proton's. */
export function searchToParams(search: AdvancedSearch): URLSearchParams {
  const params = new URLSearchParams()
  for (const name of TEXT_FIELDS) {
    const value = search[name].trim()
    if (value) params.set(name, value)
  }
  if (search.attachments) params.set('filter', 'attachments')
  return params
}

/** Whether anything is searched for (the attachments filter alone is a list filter). */
export function isSearching(search: AdvancedSearch): boolean {
  return TEXT_FIELDS.some((name) => search[name] !== '')
}

/** The criteria the list endpoint takes, with the days as moments in the reader's time zone. */
export function listCriteria(search: AdvancedSearch): { from?: string; to?: string; since?: string; until?: string; address?: string } {
  const start = (day: string) => new Date(`${day}T00:00:00`)
  const nextDay = (day: string) => {
    const date = start(day)
    date.setDate(date.getDate() + 1)
    return date
  }
  return {
    ...(search.from ? { from: search.from } : {}),
    ...(search.to ? { to: search.to } : {}),
    ...(search.since ? { since: start(search.since).toISOString() } : {}),
    // The end day is included (Proton adds a day to it).
    ...(search.until ? { until: nextDay(search.until).toISOString() } : {}),
    ...(search.address ? { address: search.address } : {}),
  }
}
