import { parseAccount } from '@kutup/chat-core/identity'
import type { ChatService } from '@kutup/chat-core/service'
import { serverAddressOf } from '@kutup/drive-core/accountName'
import { followAccountRenames } from '@kutup/drive-core/identityPins'
import { driveIdentity, forgetAccountName } from './accountNames'

// Renames of the people you chat with (docs/plans/account-ids.md): a thread
// is keyed by the account, so a rename keeps it; this writes the line saying
// so, as their own verified rename chain tells it (`followAccountRenames`:
// signed by the authority pinned for them, extending what the list holds,
// renames since they were met). Each peer is asked at most every few
// minutes and only a few per pass, newest conversations first, so a long
// contact list does not flood the server; a peer whose server label changed
// is asked at once.

const EVERY_MS = 5 * 60_000
const PER_PASS = 3

const checked = new Map<string, number>()
let running = false

/** Forget what was checked (a new session). */
export function resetRenameWatch(): void {
  checked.clear()
  running = false
}

/** Asks again about `peer` on the next pass (its server's label changed). */
export function renameSuspected(peer: string): void {
  checked.delete(peer)
}

/**
 * One pass over `peers` (account keys, newest conversation first): the few
 * that are due are followed, and a line is written for each new rename.
 * `onChange` runs when a line was written.
 */
export async function checkRenames(service: ChatService, peers: readonly string[], onChange: () => void, now = Date.now()): Promise<void> {
  const me = driveIdentity()
  if (running || !me) return
  const due = peers.filter((peer) => now - (checked.get(peer) ?? -Infinity) >= EVERY_MS).slice(0, PER_PASS)
  if (due.length === 0) return
  running = true
  try {
    const identity = await me
    let wrote = false
    for (const peer of due) {
      checked.set(peer, now)
      const account = parseAccount(peer)
      if (!account) continue
      try {
        const current = await serverAddressOf(account, true)
        if (!current) continue
        // A peer met lately may not be pinned in the account's list yet:
        // Chat's own pin, waiting for its write, stands in meanwhile.
        const pending = await service.pendingIdentityPin(account)
        let renames = await followAccountRenames(identity, account, current, pending)
        // They renamed before their pin was written: it is written now, and
        // the chain followed again into the list, so its checks (someone
        // else at their old address) know them by both addresses.
        if (pending && renames.length > 0 && (await service.writeIdentityPinNow(account))) {
          renames = await followAccountRenames(identity, account, current)
        }
        for (const rename of renames) {
          if (await service.recordPeerRenamed(account, rename)) wrote = true
        }
        if (renames.length > 0) forgetAccountName(peer)
      } catch {
        // Asked again on a later pass.
        checked.delete(peer)
      }
    }
    if (wrote) onChange()
  } finally {
    running = false
  }
}
