// Whether a collab frame is its sender's (docs/plans/one-device-list.md §8,
// slice 3). A frame is applied only when its sender account's manifest lists
// the frame's device with the key that signed it: the head for a live frame,
// the manifest the frame names for one replayed from the log. The rules are
// Rust's (`SenderManifests`, held per sender in the crypto WASM); this reads
// what they ask for (heads, history) and keeps the pins.
//
// A sender whose account was reset (the identity pins hold another
// authority, not accepted) is refused until the file is shared again to the
// new account; every refused sender is told once to `onRefused`.

import {
  collabSender,
  deliveredFrameSender,
  type AccountManifest,
  type CollabSenderHandle,
} from '@kutup/crypto/accountManifest'
import { fetchManifest, fetchManifestHistory } from '@kutup/session/devices'
import { keepManifestPin, manifestPin } from '@kutup/session/manifestPins'

/** The identity pins' word on `authority` for `account` (drive-core's `authorityVerdict`). */
export type AuthorityVerdict = (account: string, authority: string) => Promise<'pinned' | 'changed' | 'unknown'>

/** A sender whose frames are dropped: its account was reset, or a frame couldn't be verified. */
export interface SenderRefusal {
  account: string
  /** What to call the sender (its address), or the account itself. */
  name: string
  reason: 'reset' | 'unverified'
}

export interface SenderCheckOptions {
  authority: AuthorityVerdict
  /** What to call an account (drive-core's `accountNameOfKey`). */
  name?: (account: string) => Promise<string | null>
  /** Told once per sender and reason. */
  onRefused?: (refusal: SenderRefusal) => void
}

/** How often one frame's check may read a head or a manifest before it is dropped. */
const MAX_READS = 3
/** Between reads that failed (the server unreachable for a moment). */
const RETRY_MS = 500

interface Sender {
  handle: CollabSenderHandle
  /** The identity pins hold another authority: refused until shared again. */
  reset: boolean
  told: Set<SenderRefusal['reason']>
}

class ResetAccount extends Error {}

export class SenderCheck {
  private readonly senders = new Map<string, Promise<Sender>>()

  constructor(private readonly options: SenderCheckOptions) {}

  /**
   * Whether `delivered` (a frame as the server delivers it) is its sender's:
   * true to apply it. `live`: during editing; false for a frame replayed
   * from the log. Never throws; a frame that can't be verified is dropped.
   */
  async verify(delivered: Uint8Array, live: boolean): Promise<boolean> {
    let account: string
    try {
      account = await deliveredFrameSender(delivered)
    } catch {
      return false
    }
    const sender = await this.sender(account)
    if (sender.reset) return this.refuse(account, sender, 'reset')
    for (let reads = 0; ; ) {
      const verdict = sender.handle.check(delivered, live)
      if (verdict.kind === 'take') return true
      if (verdict.kind === 'refuse' || reads >= MAX_READS) return this.refuse(account, sender, 'unverified')
      try {
        if (verdict.kind === 'needHead') {
          // Once per frame: a head that still doesn't reach it refuses it.
          if (reads > 0 && !(await this.headMoved(account, sender))) {
            return this.refuse(account, sender, 'unverified')
          }
          await this.readHead(account, sender)
        } else {
          await this.readEntry(account, sender, verdict.sequence)
        }
        reads++
      } catch (error) {
        if (error instanceof ResetAccount) return this.refuse(account, sender, 'reset')
        reads++
        await new Promise((resolve) => setTimeout(resolve, RETRY_MS * reads))
      }
    }
  }

  /** Frees the WASM records. */
  close(): void {
    for (const sender of this.senders.values()) void sender.then((s) => s.handle.free(), () => {})
    this.senders.clear()
  }

  private sender(account: string): Promise<Sender> {
    let sender = this.senders.get(account)
    if (!sender) {
      sender = manifestPin(account)
        .catch(() => null)
        .then(async (pin) => ({ handle: await collabSender(account, pin), reset: false, told: new Set() }))
      this.senders.set(account, sender)
    }
    return sender
  }

  private refuse(account: string, sender: Sender, reason: SenderRefusal['reason']): false {
    if (!sender.told.has(reason)) {
      sender.told.add(reason)
      const onRefused = this.options.onRefused
      if (onRefused) {
        void (this.options.name?.(account) ?? Promise.resolve(null))
          .catch(() => null)
          .then((name) => onRefused({ account, name: name ?? account, reason }))
      }
    }
    return false
  }

  private async headMoved(account: string, sender: Sender): Promise<boolean> {
    const head = await fetchManifest(account)
    return !!head && head.sequence > (sender.handle.pin()?.sequence ?? 0)
  }

  /** The account's head, with the history from the pin to it; the pin moves with it. */
  private async readHead(account: string, sender: Sender): Promise<void> {
    const head = await fetchManifest(account)
    if (!head) throw new Error('the sender account has no manifest')
    const authority = String(head.selfAuthorityKey ?? '')
    const verdict = await this.options.authority(account, authority)
    if (verdict === 'changed') {
      sender.reset = true
      throw new ResetAccount()
    }
    const pin = sender.handle.pin()
    // The identity pins hold this authority while the pin is of another
    // incarnation: the user accepted the account's reset.
    const newIncarnation = verdict === 'pinned' && !!pin && pin.incarnationId !== head.incarnationId
    const history: AccountManifest[] | null =
      pin && !newIncarnation && head.sequence > pin.sequence + 1
        ? await fetchManifestHistory(account, pin.sequence + 1, head.sequence - 1)
        : null
    sender.handle.takeHead(head, history, newIncarnation)
    const kept = sender.handle.pin()
    if (kept) await keepManifestPin(kept).catch(() => {})
  }

  /** The account's manifest at `sequence`, for a frame from the log. */
  private async readEntry(account: string, sender: Sender, sequence: number): Promise<void> {
    const [manifest] = await fetchManifestHistory(account, sequence, sequence)
    if (!manifest || manifest.sequence !== sequence) throw new Error('the manifest was not served')
    sender.handle.takeEntry(manifest)
  }
}
