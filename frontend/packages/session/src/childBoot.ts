// Start-up for the apps that get their session from the account app
// (drive., chat.). One function so both apps behave identically.

import { isAxiosError } from 'axios'
import { loadAppDirectory } from './apps'
import { consumeFork, hasForkInLocation, requestFork, type ForkChild } from './fork'
import { restoreSession } from './persist'

export type ChildBootResult =
  /** Signed in; `next` is where a just-consumed fork asked to go. */
  | { kind: 'ready'; next?: string }
  /** Leaving for the account app; render nothing. */
  | { kind: 'redirecting' }

const ATTEMPTS_KEY = 'kutup-fork-attempts'
/** Fork round-trips allowed per tab before showing an error instead of looping. */
const MAX_ATTEMPTS = 2

function attempts(): number {
  return Number(sessionStorage.getItem(ATTEMPTS_KEY) ?? '0')
}

function askAccount(app: ForkChild): ChildBootResult {
  if (attempts() >= MAX_ATTEMPTS) {
    sessionStorage.removeItem(ATTEMPTS_KEY)
    throw new Error('the sign-in hand-off from the account app keeps failing')
  }
  sessionStorage.setItem(ATTEMPTS_KEY, String(attempts() + 1))
  requestFork(app)
  return { kind: 'redirecting' }
}

/**
 * 1. A fork in the URL (`/login#selector=…`) is consumed.
 * 2. Otherwise this origin's encrypted session blob is restored.
 * 3. Otherwise the account app is asked for a fork (and signs in first if
 *    needed).
 *
 * A fork that cannot be redeemed (reloaded link, expired after 60 s) asks for
 * a fresh one; repeated failures throw rather than bounce between origins.
 * Network failures throw with any stored session intact.
 */
export async function bootChildApp(app: ForkChild): Promise<ChildBootResult> {
  await loadAppDirectory()
  if (hasForkInLocation()) {
    try {
      const next = await consumeFork()
      sessionStorage.removeItem(ATTEMPTS_KEY)
      return { kind: 'ready', next }
    } catch (error) {
      if (isAxiosError(error) && !error.response) throw error
      return askAccount(app)
    }
  }
  if ((await restoreSession()) === 'restored') {
    sessionStorage.removeItem(ATTEMPTS_KEY)
    return { kind: 'ready' }
  }
  return askAccount(app)
}
