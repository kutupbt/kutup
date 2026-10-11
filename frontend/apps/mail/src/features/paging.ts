/** How many pages `total` rows fill, at least one (Proton's `pageCount`). */
export function pageCount(total: number, pageSize: number): number {
  return Math.max(1, Math.ceil(total / pageSize))
}

/**
 * The page numbers Proton's list foot shows (MailboxListPagination), from
 * 1: the first, the last and those around the current one, with `gap`
 * where numbers are skipped.
 */
export function pageNumbers(page: number, pages: number): (number | 'gap')[] {
  const around = page === 1 ? [1, 2, 3] : page === pages ? [pages - 2, pages - 1, pages] : [page - 1, page, page + 1]
  const shown = [...new Set([1, ...around, pages])].filter((n) => n >= 1 && n <= pages).sort((a, b) => a - b)
  const out: (number | 'gap')[] = []
  shown.forEach((n, i) => {
    if (i > 0 && n - shown[i - 1] > 1) out.push('gap')
    out.push(n)
  })
  return out
}

/** The page (from 1) in the address bar's `page`; anything else is the first. */
export function pageFromParams(params: URLSearchParams): number {
  const page = Number(params.get('page'))
  return Number.isInteger(page) && page > 1 ? page : 1
}
