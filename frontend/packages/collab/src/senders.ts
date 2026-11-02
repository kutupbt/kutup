// Whether a collab frame is its sender's (docs/plans/one-device-list.md §8,
// slice 3). A frame is applied only when its sender account's manifest lists
// the frame's device with the key that signed it: the head for a live frame,
// the manifest the frame names for one replayed from the log. The rules are
// Rust's (`SenderManifests`, held per sender in the crypto WASM); this reads
// what they ask for (heads, history) and keeps the pins.
//
// Three answers, and they are not the same:
// - `take`: apply it.
// - `forged`: proven not its sender's (its manifest is held and doesn't list
//   the device with that key). Dropped; the editor may move past it.
// - `unverified`: can't be told now (a read failed, the read budget is spent,
//   the account was reset). Dropped for now, but the editor must not move its
//   log position past it, so a save never trims it away: it is replayed and
//   checked again later.
//
// A sender whose account was reset (the identity pins hold another
// authority, or don't know the account while its rollback pin names another
// incarnation) is refused until the share is made again or the user trusts
// the new account; every refused sender is told once per reason.

import {
  collabSender,
  deliveredFrameSender,
  type AccountManifest,
  type CollabSenderHandle,
} from '@kutup/crypto/accountManifest'
import { fetchManifest, fetchManifestHistory } from '@kutup/session/devices'
import { forgetManifestPin, keepManifestPin, manifestPin } from '@kutup/session/manifestPins'

/** The identity pins' word on `authority` for `account` (drive-core's `authorityVerdict`). */
export type AuthorityVerdict = (account: string, authority: string) => Promise<'pinned' | 'changed' | 'unknown'>

/** What to do with a frame. */
export type FrameVerdict = 'take' | 'forged' | 'unverified'

/** A sender whose frames are dropped. */
export interface SenderRefusal {
  account: string
  /** What to call the sender (its address), or the account itself. */
  name: string
  /** `reset`: the account was reset; `unverified`: some frames couldn't be checked or didn't check out. */
  reason: 'reset' | 'unverified'
  /**
   * For a reset the identity pins don't know about: trust the account's new
   * keys (forget the old pin), and replay what was held.
   */
  trust?: () => Promise<void>
}

export interface SenderCheckOptions {
  authority: AuthorityVerdict
  /** What to call an account (drive-core's `accountNameOfKey`). */
  name?: (account: string) => Promise<string | null>
  /** Told once per sender and reason. */
  onRefused?: (refusal: SenderRefusal) => void
}

/** Reads one frame's check may make before it is held. */
const MAX_READS_PER_FRAME = 2
/** Reads per sender per minute: past it, frames are held, not fetched for. */
const MAX_READS_PER_MINUTE = 20
/** How long a failed read is not tried again. */
const FAILURE_TTL_MS = 60_000

interface Sender {
  handle: CollabSenderHandle
  /** The account was reset: held until trusted or shared again. */
  reset: boolean
  /** A reset the identity pins don't know about: the user may trust it here. */
  trustable: boolean
  told: Set<SenderRefusal['reason']>
  /** Reads that failed, by what was read, until when not to try again. */
  failed: Map<string, number>
  /** This minute's reads. */
  reads: { since: number; count: number }
}

class ResetAccount extends Error {
  constructor(readonly trustable: boolean) {
    super('the account was reset')
  }
}

export class SenderCheck {
  private readonly senders = new Map<string, Promise<Sender>>()
  private readonly trusted = new Set<() => void>()

  constructor(private readonly options: SenderCheckOptions) {}

  /**
   * What to do with `delivered` (a frame as the server delivers it). `live`:
   * during editing; false for a frame replayed from the log. Never throws.
   */
  async verify(delivered: Uint8Array, live: boolean): Promise<FrameVerdict> {
    let account: string
    try {
      account = await deliveredFrameSender(delivered)
    } catch {
      return 'forged'
    }
    const sender = await this.sender(account)
    if (sender.reset) return this.refuse(account, sender, 'reset', 'unverified')
    for (let reads = 0; ; reads++) {
      const verdict = sender.handle.check(delivered, live)
      if (verdict.kind === 'take') return 'take'
      if (verdict.kind === 'refuse') return this.refuse(account, sender, 'unverified', 'forged')
      if (reads >= MAX_READS_PER_FRAME) return this.refuse(account, sender, 'unverified', 'unverified')
      const what = verdict.kind === 'needHead' ? 'head' : `history:${verdict.sequence}-${verdict.through}`
      if (!this.mayRead(sender, what)) return this.refuse(account, sender, 'unverified', 'unverified')
      try {
        if (verdict.kind === 'needHead') await this.readHead(account, sender)
        else await this.readHistory(account, sender, verdict.sequence, verdict.through)
      } catch (error) {
        if (error instanceof ResetAccount) return this.refuse(account, sender, 'reset', 'unverified')
        sender.failed.set(what, Date.now() + FAILURE_TTL_MS)
        return this.refuse(account, sender, 'unverified', 'unverified')
      }
    }
  }

  /**
   * Calls `listener` when a sender is trusted again (`SenderRefusal.trust`),
   * so what was held is replayed (a session resyncs its socket). Returns the
   * unsubscribe.
   */
  whenTrusted(listener: () => void): () => void {
    this.trusted.add(listener)
    return () => this.trusted.delete(listener)
  }

  /** Frees the WASM records. */
  close(): void {
    this.trusted.clear()
    for (const sender of this.senders.values()) void sender.then((s) => s.handle.free(), () => {})
    this.senders.clear()
  }

  private sender(account: string): Promise<Sender> {
    let sender = this.senders.get(account)
    if (!sender) {
      sender = this.fresh(account)
      this.senders.set(account, sender)
    }
    return sender
  }

  private async fresh(account: string): Promise<Sender> {
    const pin = await manifestPin(account).catch(() => null)
    return {
      handle: await collabSender(account, pin),
      reset: false,
      trustable: false,
      told: new Set(),
      failed: new Map(),
      reads: { since: Date.now(), count: 0 },
    }
  }

  /** Whether `what` may be read now: not failed lately, and within the budget. */
  private mayRead(sender: Sender, what: string): boolean {
    const now = Date.now()
    const until = sender.failed.get(what)
    if (until !== undefined && until > now) return false
    if (now - sender.reads.since >= 60_000) sender.reads = { since: now, count: 0 }
    if (sender.reads.count >= MAX_READS_PER_MINUTE) return false
    sender.reads.count++
    return true
  }

  private refuse(
    account: string,
    sender: Sender,
    reason: SenderRefusal['reason'],
    verdict: Exclude<FrameVerdict, 'take'>,
  ): Exclude<FrameVerdict, 'take'> {
    if (!sender.told.has(reason)) {
      sender.told.add(reason)
      const onRefused = this.options.onRefused
      if (onRefused) {
        const trust = reason === 'reset' && sender.trustable ? () => this.trust(account) : undefined
        void (this.options.name?.(account) ?? Promise.resolve(null))
          .catch(() => null)
          .then((name) => onRefused({ account, name: name ?? account, reason, trust }))
      }
    }
    return verdict
  }

  /** Trusts `account`'s new keys: its old pin goes, and what was held is replayed. */
  private async trust(account: string): Promise<void> {
    await forgetManifestPin(account)
    const old = this.senders.get(account)
    this.senders.set(account, this.fresh(account))
    void old?.then((s) => s.handle.free(), () => {})
    for (const listener of this.trusted) listener()
  }

  /** The account's head, with the history from the pin to it; the pin moves with it. */
  private async readHead(account: string, sender: Sender): Promise<void> {
    const head = await fetchManifest(account)
    if (!head) throw new Error('the sender account has no manifest')
    const verdict = await this.options.authority(account, String(head.selfAuthorityKey ?? ''))
    const pin = sender.handle.pin()
    const otherIncarnation = !!pin && pin.incarnationId !== head.incarnationId
    if (verdict === 'changed' || (verdict === 'unknown' && otherIncarnation)) {
      sender.reset = true
      // The identity pins don't know it: only this pin holds the old keys.
      sender.trustable = verdict === 'unknown'
      throw new ResetAccount(sender.trustable)
    }
    // The identity pins hold this authority while the pin is of another
    // incarnation: the user accepted the account's reset.
    const newIncarnation = verdict === 'pinned' && otherIncarnation
    const history: AccountManifest[] | null =
      pin && !newIncarnation && head.sequence > pin.sequence + 1
        ? await fetchManifestHistory(account, pin.sequence + 1, head.sequence - 1)
        : null
    sender.handle.takeHead(head, history, newIncarnation)
    const kept = sender.handle.pin()
    if (kept) await keepManifestPin(kept).catch(() => {})
  }

  /** The run of manifests a frame from the log needs, linked up to the head. */
  private async readHistory(account: string, sender: Sender, sequence: number, through: number): Promise<void> {
    const run = await fetchManifestHistory(account, sequence, through)
    sender.handle.takeHistory(run)
  }
}
