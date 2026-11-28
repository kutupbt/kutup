// Restoring from the trash when the name is taken where an entry comes back:
// the screens ask, and a source throws RestoreCancelled when the person says no.

/** Restoring needs a name: what is asked, and the name offered. */
export interface RestoreNameQuestion {
  name: string
  /** The first free `name (n)` where it comes back. */
  suggested: string
}

/** Asks the person whether to restore under the offered name; false: leave it in the trash. */
export type AskRestoreName = (question: RestoreNameQuestion) => Promise<boolean>

/** A restore the person called off (its name is taken where it comes back). */
export class RestoreCancelled extends Error {
  constructor() {
    super('restore cancelled')
  }
}
