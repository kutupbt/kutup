// The one gate every opener of this origin's local storage waits on
// (docs/plans/api-surface.md §5): the server instance check, which may clear
// the storage before anything reads it. The session package registers the
// check at boot (configureClient); without it (tests, a Worker) the gate is
// open. A failed check opens the gate too: the page then works offline with
// what it has, and boot itself reports the failure.

let starter: (() => Promise<void>) | null = null
let gate: Promise<void> | null = null

/** Registers the check every opener waits for (once per page). */
export function setStorageGate(start: () => Promise<void>): void {
  starter = start
  gate = null
}

/** Resolves once this origin's storage may be read. */
export function storageReady(): Promise<void> {
  if (!starter) return Promise.resolve()
  gate ??= starter().catch(() => undefined)
  return gate
}
