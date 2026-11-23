// How strong a password is (docs/plans/pass-gaps-3.md, A1, Q-1): zxcvbn, as
// KeePassXC uses it, loaded on first use (its dictionaries are ~800 kB, so
// not with the app); until it is there, the generator's character-set
// estimate. Nothing leaves the device.

import { useEffect, useState } from 'react'
import { retryImport } from '@kutup/crypto/retry'
import { strengthOf } from './generator'

export type Strength = 'weak' | 'fair' | 'strong'
export type StrengthOf = (password: string) => Strength

type Zxcvbn = (password: string) => { score: number }

let loading: Promise<Zxcvbn> | null = null
function loadZxcvbn(): Promise<Zxcvbn> {
  if (!loading) {
    loading = retryImport(() => import('zxcvbn')).then((module) => module.default)
    loading.catch(() => {
      loading = null
    })
  }
  return loading
}

/** zxcvbn's score (0–4) as the report's three steps, as KeePassXC groups them. */
export function strengthOfScore(score: number): Strength {
  return score <= 1 ? 'weak' : score === 2 ? 'fair' : 'strong'
}

/** The strength function to use now: zxcvbn once loaded, the estimate before. */
export function useStrength(): StrengthOf {
  const [zxcvbn, setZxcvbn] = useState<Zxcvbn | null>(null)
  useEffect(() => {
    let cancelled = false
    void loadZxcvbn().then(
      (fn) => {
        if (!cancelled) setZxcvbn(() => fn)
      },
      () => undefined,
    )
    return () => {
      cancelled = true
    }
  }, [])
  // Long values are cut for zxcvbn (its cost grows with length); past 100
  // characters nothing is weak by its measure anyway.
  return zxcvbn ? (password) => (password ? strengthOfScore(zxcvbn(password.slice(0, 100)).score) : 'weak') : strengthOf
}
