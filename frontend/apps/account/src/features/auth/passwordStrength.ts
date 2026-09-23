import { useEffect, useState } from 'react'

type Zxcvbn = (password: string) => { score: number }

/**
 * zxcvbn is ~800 kB of dictionaries, so it loads on first use rather than
 * with the app — once, shared by every caller.
 */
let loading: Promise<Zxcvbn> | null = null
function loadZxcvbn(): Promise<Zxcvbn> {
  loading ??= import('zxcvbn').then((module) => module.default)
  return loading
}

/**
 * The score (0–4) a submit handler checks. Awaits the library, so a fast
 * "Continue" never judges a password before it can be measured. The server
 * never sees the password — only a key derived from it — so this is the only
 * place a weak one can be refused.
 */
export async function passwordScore(password: string): Promise<number> {
  const zxcvbn = await loadZxcvbn()
  return password ? zxcvbn(password).score : 0
}

/** The live score for the meter, or null while the library loads. */
export function usePasswordStrength(password: string): number | null {
  const [zxcvbn, setZxcvbn] = useState<Zxcvbn | null>(null)
  useEffect(() => {
    let cancelled = false
    void loadZxcvbn().then((fn) => {
      if (!cancelled) setZxcvbn(() => fn)
    })
    return () => {
      cancelled = true
    }
  }, [])
  if (!zxcvbn) return null
  return password ? zxcvbn(password).score : 0
}

/** The weakest score accepted for a new password. */
export const MIN_PASSWORD_SCORE = 2
