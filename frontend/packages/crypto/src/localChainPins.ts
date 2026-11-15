// The newest state this device has seen of each account-private chain (the
// Photos library, the Chat attachment ledger): the chain's revision (or
// cursor) and its digest there, so a server that hands back an older state,
// or another state at the same revision, is caught.
//
// The pins live in the revision guard's IndexedDB store (`revisionGuard.ts`),
// beside its entries: each is an account record (purpose `LocalChainPin`,
// Rust `local_chain_pin`) under the master key, bound to the account's key
// binding and to its entry name, a keyed hash of the chain's scope and id.
// Anyone with the disk can delete a pin or put back an older copy of it, but
// can neither read pins nor set one to a state of their choosing. A pin that
// is missing or does not open (altered, moved, another account's) is
// "unseen": the next state read is trusted and pinned, as on a new device.

import type { ObjectIdKey } from './accountRoots'
import { toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'
import { indexedDbRevisionStore, memoryRevisionStore, serialized, type RevisionStore } from './revisionGuard'

/** The account's keys for its pins (Rust `local_chain_pin::PinKeys`). */
export interface ChainPinKeys {
  entryId(scope: string, id: string): string
  /** `revision` in decimal, `digestHex` 32 bytes of lowercase hex. */
  sealPin(entry: string, revision: string, digestHex: string): string
  /** Throws when the pin was moved to another entry, is another account's, or was altered. */
  openPin(entry: string, sealed: string): { revision: string; digestHex: string }
}

/** A chain's newest state seen on this device. */
export interface ChainPin {
  revision: bigint
  /** The chain's digest at `revision`, lowercase hex. */
  digest: string
}

const MAX_U64 = 0xffff_ffff_ffff_ffffn

function checkPin(revision: bigint, digest: string): void {
  if (revision < 0n || revision > MAX_U64) throw new Error(`invalid chain pin revision ${revision}`)
  if (!/^[0-9a-f]{64}$/.test(digest)) throw new Error('a chain pin digest is 32 bytes of lowercase hex')
}

export class LocalChainPins {
  constructor(
    private readonly store: RevisionStore,
    private readonly keys: () => Promise<ChainPinKeys>,
  ) {}

  private async entry(scope: string, id: string): Promise<{ keys: ChainPinKeys; entry: string }> {
    const keys = await this.keys()
    return { keys, entry: keys.entryId(scope, id) }
  }

  private async read(keys: ChainPinKeys, entry: string): Promise<ChainPin | null> {
    const sealed = await this.store.get(entry)
    if (!sealed) return null
    try {
      const pin = keys.openPin(entry, sealed)
      return { revision: BigInt(pin.revision), digest: pin.digestHex }
    } catch {
      // Altered, moved or another account's: no better than deleted, which
      // the disk allows anyway.
      return null
    }
  }

  /** The newest state seen of chain `scope`/`id`: null when none was, or its pin does not open. */
  async loadPin(scope: string, id: string): Promise<ChainPin | null> {
    const { keys, entry } = await this.entry(scope, id)
    return this.read(keys, entry)
  }

  /**
   * Remembers `revision` and `digest` as the newest state seen of chain
   * `scope`/`id`, never moving back: written only above the pinned revision
   * (true when written). A different digest at the pinned revision is not
   * written either; the caller detects it on load.
   */
  async storePin(scope: string, id: string, revision: bigint | number, digest: string): Promise<boolean> {
    const value = BigInt(revision)
    checkPin(value, digest)
    const { keys, entry } = await this.entry(scope, id)
    // One read-then-write at a time per entry, so two stores at once cannot
    // leave the lower of them pinned.
    return serialized(entry, async () => {
      const known = await this.read(keys, entry)
      if (known && known.revision >= value) return false
      await this.store.put(entry, keys.sealPin(entry, value.toString(), digest))
      return true
    })
  }
}

let shared: RevisionStore | null = null
/** By account (its key binding): the pins, for the master key they were made with. */
const pins = new Map<string, { masterKey: string; pins: LocalChainPins }>()
/** Set by tests: keys that need no WASM. */
let testKeys: ((binding: string) => ChainPinKeys) | null = null

/**
 * The account's chain pins over the browser's store, sealed for its master
 * key and key binding (`envelopeBinding`).
 */
export function localChainPins(session: {
  masterKey: Uint8Array
  roots: { objectIdKey: ObjectIdKey }
  envelopeBinding: string
}): LocalChainPins {
  const masterKey = toBase64(session.masterKey)
  const objectIdKey = session.roots.objectIdKey
  const binding = session.envelopeBinding
  const known = pins.get(binding)
  // Made again when the master key is another (the keys are both).
  if (known?.masterKey === masterKey) return known.pins
  shared ??= indexedDbRevisionStore()
  let keys: Promise<ChainPinKeys> | null = null
  const forTests = testKeys
  const load = (): Promise<ChainPinKeys> => {
    if (forTests) return Promise.resolve(forTests(binding))
    keys ??= getCryptoWasm()
      .then((wasm): ChainPinKeys => new wasm.LocalChainPins(masterKey, objectIdKey, binding))
      .catch((error: unknown) => {
        // Not kept: the next call loads again.
        keys = null
        throw error
      })
    return keys
  }
  const made = new LocalChainPins(shared, load)
  pins.set(binding, { masterKey, pins: made })
  return made
}

/** Forgets every account's pins (a fresh device) and uses keys that need no WASM: for tests. */
export function resetLocalChainPinsForTesting(): void {
  shared = memoryRevisionStore()
  pins.clear()
  testKeys = plainChainPinKeysForTesting
}

/** Keys for tests: entries named as they are, pins as text, checked against their entry. */
export function plainChainPinKeysForTesting(account: string): ChainPinKeys {
  return {
    entryId: (scope, id) => `${account}:${scope}:${id}`,
    sealPin: (entry, revision, digestHex) => `${entry}|${revision}|${digestHex}`,
    openPin: (entry, sealed) => {
      const [named, revision, digestHex] = sealed.split('|')
      if (named !== entry || revision === undefined || digestHex === undefined) throw new Error('moved')
      return { revision, digestHex }
    },
  }
}
