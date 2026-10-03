// The name a person last joined a link call with, kept in this browser so
// the next call opens with it filled in. It is only a convenience: nothing
// else reads it.

const KEY = 'kutup-call-name'
/** What the join form accepts (the sealed name holds 124 bytes of UTF-8). */
export const MAX_CALL_NAME_LENGTH = 40

export function rememberedCallName(): string {
  try {
    return (localStorage.getItem(KEY) ?? '').slice(0, MAX_CALL_NAME_LENGTH)
  } catch {
    return ''
  }
}

export function rememberCallName(name: string): void {
  const trimmed = name.trim().slice(0, MAX_CALL_NAME_LENGTH)
  if (!trimmed) return
  try {
    localStorage.setItem(KEY, trimmed)
  } catch {
    // Private browsing: the form simply starts empty next time.
  }
}
