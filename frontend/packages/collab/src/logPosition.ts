// How far into the relay's log a document is known to be complete: every
// kept frame up to `applied` is in it. Saved versions record it (so trimming
// the log never removes an edit they lack) and reconnects resume from it.
//
// Positions arrive after their frames (`stored` one by one, `replayed` for a
// whole replay); one announced beyond a gap waits until the gap closes. A
// frame held back as unverified (its sender couldn't be checked now,
// docs/plans/one-device-list.md §8, slice 3) stops the position where it is
// for the rest of the connection: no save records a position past it, so the
// server never trims it away, and the next connection replays it.

export class LogPosition {
  private value = 0
  private readonly announced = new Set<number>()
  private holding = false

  /** Every kept frame up to here is in the document. */
  get applied(): number {
    return this.value
  }

  /** Whether a frame was held back on this connection. */
  get held(): boolean {
    return this.holding
  }

  /** The document was loaded from a saved state through `seq`. */
  loaded(seq: number): void {
    this.value = seq
  }

  /** `stored`: the frame just received is kept at `seq`. */
  stored(seq: number): void {
    if (seq > this.value) this.announced.add(seq)
    this.advance()
  }

  /** `replayed`: the replay reached `throughSeq` (or a newer saved version, `version`). */
  replayed(throughSeq: number, version = 0): void {
    if (!this.holding) this.value = Math.max(this.value, throughSeq, version)
    this.advance()
  }

  /** A frame was held back as unverified: the position stops here for this connection. */
  hold(): void {
    this.holding = true
  }

  /** A new connection: it replays from `applied`, so what was held is checked again. */
  connected(): void {
    this.holding = false
    this.announced.clear()
  }

  private advance(): void {
    if (this.holding) return
    while (this.announced.has(this.value + 1)) {
      this.announced.delete(this.value + 1)
      this.value += 1
    }
    for (const seq of this.announced) if (seq <= this.value) this.announced.delete(seq)
  }
}
