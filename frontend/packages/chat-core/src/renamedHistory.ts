import { foldAddress } from '@kutup/crypto/accountRename'
import { canonicalAccountAddress, parseAccountAddress } from './identity'
import type { ChatHistoryEntry, ChatRenameAliases } from './types'

/**
 * Restored history under the addresses peers have now
 * (docs/plans/username-renames.md). A backup keeps each record's direct
 * conversation and sender as they were when it was made; a peer that renamed
 * since is under its new address in the live store, so its restored records
 * go to the same thread. A name someone else took later is theirs from then
 * on: a record from that time stays under it (`reusedAtMs`).
 */
export async function throughRenameAliases(
  entries: readonly ChatHistoryEntry[],
  aliases: ChatRenameAliases,
): Promise<ChatHistoryEntry[]> {
  if (Object.keys(aliases).length === 0) return [...entries]
  const folds = new Map<string, string | null>()
  const resolve = async (address: string, atMs: number): Promise<string | null> => {
    if (!folds.has(address)) folds.set(address, await foldAddress(address))
    const folded = folds.get(address)
    const alias = folded ? aliases[folded] : undefined
    if (!alias || alias.to === address) return null
    return alias.reusedAtMs === undefined || atMs < alias.reusedAtMs ? alias.to : null
  }
  const out: ChatHistoryEntry[] = []
  for (const entry of entries) {
    if (entry.conversation.kind !== 'direct') {
      out.push(entry)
      continue
    }
    const peer = await resolve(canonicalAccountAddress(entry.conversation.address), entry.timestampMs)
    const address = peer ? parseAccountAddress(peer) : null
    if (!address) {
      out.push(entry)
      continue
    }
    const sender = entry.direction === 'incoming' ? ((await resolve(entry.sender, entry.timestampMs)) ?? entry.sender) : entry.sender
    out.push({ ...entry, conversation: { kind: 'direct', address }, sender })
  }
  return out
}
