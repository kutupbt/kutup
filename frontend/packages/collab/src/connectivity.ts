// Whether the live editing socket can be opened at all from this network.
//
// One page edits one document, so this is page-wide: every transport says
// how its connection attempts end, and the editor page reads the count. A
// socket that closes before it ever opened is a failed attempt; one that
// opens clears the count. The page decides what a run of failures means
// (a gateway that blocks WebSockets, or a server that is simply away).

let failures = 0
const listeners = new Set<() => void>()

/** Called by a transport when a connection attempt opened or closed unopened. */
export function reportCollabSocket(opened: boolean): void {
  const next = opened ? 0 : failures + 1
  if (next === failures) return
  failures = next
  for (const listener of listeners) listener()
}

/** Connection attempts in a row that never opened. */
export function collabSocketFailures(): number {
  return failures
}

export function subscribeCollabConnectivity(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

/** Test seam. */
export function resetCollabConnectivityForTesting(): void {
  failures = 0
}
