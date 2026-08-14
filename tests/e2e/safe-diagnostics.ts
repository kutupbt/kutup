import { mkdirSync, writeFileSync } from 'node:fs'
import { isAbsolute, resolve } from 'node:path'

const SAFE_NAME = /^[a-z][a-z0-9-]{0,63}$/

/**
 * Persist only an allow-listed durable boundary and numeric counters.
 *
 * Raw Playwright traces and page snapshots can contain recovery phrases,
 * credentials, ciphertext, or stable account identifiers. Sensitive CI jobs
 * disable those artifacts and use this deliberately narrow diagnostic instead.
 */
export function recordSafeCheckpoint(
  scope: string,
  checkpoint: string,
  counts: Record<string, number> = {},
): void {
  const configured = process.env.KUTUP_E2E_DIAGNOSTICS_DIR
  if (!configured) return
  if (!SAFE_NAME.test(scope) || !SAFE_NAME.test(checkpoint)) {
    throw new Error('unsafe E2E diagnostic name')
  }
  for (const [name, value] of Object.entries(counts)) {
    if (!SAFE_NAME.test(name) || !Number.isSafeInteger(value) || value < 0) {
      throw new Error('unsafe E2E diagnostic count')
    }
  }

  const directory = isAbsolute(configured) ? configured : resolve(process.cwd(), configured)
  mkdirSync(directory, { recursive: true, mode: 0o700 })
  writeFileSync(
    resolve(directory, `${scope}.json`),
    `${JSON.stringify({ version: 1, scope, checkpoint, counts }, null, 2)}\n`,
    { encoding: 'utf8', mode: 0o600 },
  )
}
