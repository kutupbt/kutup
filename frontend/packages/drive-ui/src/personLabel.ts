import type { IdentityStatus } from '@kutup/drive-core/identityPins'

type T = (key: string, values?: Record<string, string>) => string

/**
 * `label`, with who the person is when the address does not say: the
 * account's own name when it is another one (as Signal shows an account's
 * own name, never what was typed), or the address they held before.
 */
export function personLabel(t: T, label: string, status: IdentityStatus | undefined): string {
  const name = status?.kind === 'ok' || status?.kind === 'someoneElse' ? status.name : undefined
  if (name) return `${label} (${t('identityCheck.knownAs', { name })})`
  const formerly = status?.kind === 'ok' ? status.formerly : undefined
  return formerly ? `${label} (${t('identityCheck.renamed.formerly', { formerly })})` : label
}

/** The translation key of a doubt's text: the one naming where the person they knew is now, when known. */
export function someoneElseKey(base: 'body' | 'shareBody', status: IdentityStatus | undefined): string {
  return status?.kind === 'someoneElse' && status.now ? `${base}Now` : base
}
