/**
 * The value that means "no filter", for a select that offers one.
 *
 * **Radix throws on `value=""`.** It reserves the empty string to mean "clear
 * the selection and show the placeholder", so an item carrying it is a runtime
 * error rather than a type error — twenty-one of the native selects being
 * replaced use `<option value="">All clients</option>` for exactly this, and
 * every one of them would have thrown on first render.
 *
 * So "any" needs a value that is not empty, and it must never leave the
 * component: it is a rendering detail, not a filter the server has ever heard
 * of. [`toSelect`] and [`fromSelect`] are the boundary, and the sentinel
 * appears on neither side of it.
 *
 * The sentinel is deliberately not a plausible id or slug, so a bug that let it
 * escape into a URL would be obvious in the address bar rather than silently
 * matching nothing.
 */
export const SELECT_ANY = '__any__'

/** A filter value on its way *into* a `Select`. Empty becomes the sentinel. */
export function toSelect(value: string): string {
  return value === '' ? SELECT_ANY : value
}

/** A `Select` value on its way *out*. The sentinel becomes empty again. */
export function fromSelect(value: string): string {
  return value === SELECT_ANY ? '' : value
}
