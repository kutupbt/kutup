/**
 * The form two names are compared in: NFC, Unicode's default lowercase, NFC —
 * what `kutup_crypto::drive_names::canonical_name` does (both lowercase
 * without a locale; tested against it). Every source compares names so.
 */
export function canonicalName(name: string): string {
  return name.normalize('NFC').toLowerCase().normalize('NFC')
}
