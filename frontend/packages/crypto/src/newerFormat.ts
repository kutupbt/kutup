// The three outcomes of opening a sealed format (docs/plans/format-evolution.md,
// rule 5): it opens, it is corrupt, or it is newer than this client. Rust
// reports the last as an error whose text starts with `newer format: `
// (`kutup_crypto::error::NEWER_FORMAT_PREFIX`). A newer object is kept as it
// is: show "update Kutup to open this", never delete, overwrite or repair it.

const NEWER_FORMAT_PREFIX = 'newer format: '

/** Whether `error` says the object was written by a newer Kutup than this one. */
export function isNewerFormatError(error: unknown): boolean {
  const message = typeof error === 'string' ? error : error instanceof Error ? error.message : undefined
  return typeof message === 'string' && message.startsWith(NEWER_FORMAT_PREFIX)
}
