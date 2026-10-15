import { foldAddress } from '@kutup/crypto/accountRename'
import { canonicalAccountAddress, parseAccountAddress } from './identity'
import type { ChatHistoryEntry } from './types'

/**
 * Restored history under the addresses peers have now
 * (docs/plans/username-renames.md). A backup keeps each record's direct
 * conversation and sender as they were when it was made; a peer that renamed
 * since is under its new address in the live store, so its restored records
 * go to the same thread. `aliases`: folded old address → current address.
 */
export async function throughRenameAliases(
  entries: readonly ChatHistoryEntry[],
  aliases: Readonly<Record<string, string>>,
): Promise<ChatHistoryEntry[]> {
  if (Object.keys(aliases).length === 0) return [...entries]
  const now = new Map<string, string | null>()
  const resolve = async (address: string): Promise<string | null> => {
    if (!now.has(address)) {
      const folded = await foldAddress(address)
      const current = folded ? aliases[folded] : undefined
      now.set(address, current && current !== address ? current : null)
    }
    return now.get(address)!
  }
  const out: ChatHistoryEntry[] = []
  for (const entry of entries) {
    if (entry.conversation.kind !== 'direct') {
      out.push(entry)
      continue
    }
    const peer = await resolve(canonicalAccountAddress(entry.conversation.address))
    const address = peer ? parseAccountAddress(peer) : null
    if (!address) {
      out.push(entry)
      continue
    }
    const sender = entry.direction === 'incoming' ? ((await resolve(entry.sender)) ?? entry.sender) : entry.sender
    out.push({ ...entry, conversation: { kind: 'direct', address }, sender })
  }
  return out
}
