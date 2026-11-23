// What a vault key change asks (docs/plans/pass-parity.md, "Change the
// vault's key"): each part of the key kept, replaced or dropped, as
// KeePassXC's database key settings do. The dialog's submit checks the same
// rules, so Enter cannot get past them.

/** What the vault's key is made of now. */
export interface KeyParts {
  password: boolean
  keyFile: boolean
}

export type PasswordChoice = 'keep' | 'new' | 'none'
export type KeyFileChoice = 'keep' | 'generate' | 'choose' | 'none'

export interface KeyChangeForm {
  now: KeyParts
  password: PasswordChoice
  newPassword: string
  confirm: string
  keyFile: KeyFileChoice
  /** A key file was generated (and offered as a download). */
  generated: boolean
  /** The person said they saved the generated key file. */
  generatedSaved: boolean
  /** A key file was chosen. */
  chosen: boolean
}

export type KeyChangeProblem =
  /** Neither a password nor a key file would be left. */
  | 'noKey'
  /** Everything kept: nothing to change. */
  | 'unchanged'
  | 'emptyPassword'
  | 'mismatch'
  /** A generated key file not yet made, or not yet said to be saved. */
  | 'saveKeyFile'
  | 'chooseKeyFile'

/** The first thing stopping the change, or null when it can be made. */
export function keyChangeProblem(form: KeyChangeForm): KeyChangeProblem | null {
  const password = form.password === 'keep' ? form.now.password : form.password === 'new'
  const keyFile = form.keyFile === 'keep' ? form.now.keyFile : form.keyFile !== 'none'
  if (!password && !keyFile) return 'noKey'
  // A part kept, or dropped when the key never had it, is no change.
  const samePassword = form.password === 'keep' || (form.password === 'none' && !form.now.password)
  const sameKeyFile = form.keyFile === 'keep' || (form.keyFile === 'none' && !form.now.keyFile)
  if (samePassword && sameKeyFile) return 'unchanged'
  if (form.password === 'new' && !form.newPassword) return 'emptyPassword'
  if (form.password === 'new' && form.newPassword !== form.confirm) return 'mismatch'
  if (form.keyFile === 'generate' && !(form.generated && form.generatedSaved)) return 'saveKeyFile'
  if (form.keyFile === 'choose' && !form.chosen) return 'chooseKeyFile'
  return null
}

/** The choices a key part offers: keep only what the key has. */
export function passwordChoices(now: KeyParts): PasswordChoice[] {
  return now.password ? ['keep', 'new', 'none'] : ['none', 'new']
}

export function keyFileChoices(now: KeyParts): KeyFileChoice[] {
  return now.keyFile ? ['keep', 'generate', 'choose', 'none'] : ['none', 'generate', 'choose']
}

/** A generated key file's download name: KeePassXC's `.keyx`. */
export function keyFileName(vaultName: string): string {
  const base =
    Array.from(vaultName)
      .filter((c) => c.charCodeAt(0) >= 0x20 && !'\\/:*?"<>|'.includes(c))
      .join('')
      .trim() || 'vault'
  return `${base}.keyx`
}

/** What a new vault's key asks: a password and/or a key file, nothing to keep. */
export interface NewVaultKeyForm {
  password: string
  confirm: string
  keyFile: Exclude<KeyFileChoice, 'keep'>
  generated: boolean
  generatedSaved: boolean
  chosen: boolean
}

/**
 * The first thing stopping a vault being made with a key the person
 * chooses, or null: the rules of a key change from no key at all, so a
 * typed password must be typed twice and a generated key file said saved
 * (as KeePassXC's New Database wizard asks).
 */
export function newVaultKeyProblem(form: NewVaultKeyForm): Exclude<KeyChangeProblem, 'unchanged' | 'emptyPassword'> | null {
  const problem = keyChangeProblem({
    now: { password: false, keyFile: false },
    password: form.password ? 'new' : 'none',
    newPassword: form.password,
    confirm: form.confirm,
    keyFile: form.keyFile,
    generated: form.generated,
    generatedSaved: form.generatedSaved,
    chosen: form.chosen,
  })
  // Nothing chosen is no key (never "unchanged"); an empty password is none.
  return problem === 'unchanged' || problem === 'emptyPassword' ? 'noKey' : problem
}

/** The key file choices a new vault offers. */
export const NEW_VAULT_KEY_FILE_CHOICES = keyFileChoices({ password: false, keyFile: false }) as NewVaultKeyForm['keyFile'][]
