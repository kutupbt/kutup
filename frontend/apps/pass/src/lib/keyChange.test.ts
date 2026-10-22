import { describe, expect, it } from 'vitest'
import { keyChangeProblem, keyFileChoices, keyFileName, passwordChoices, type KeyChangeForm } from './keyChange'

const form = (over: Partial<KeyChangeForm> = {}): KeyChangeForm => ({
  now: { password: true, keyFile: false },
  password: 'keep',
  newPassword: '',
  confirm: '',
  keyFile: 'keep',
  generated: false,
  generatedSaved: false,
  chosen: false,
  ...over,
})

describe('a vault key change', () => {
  it('keeps one part at least, and changes something', () => {
    expect(keyChangeProblem(form())).toBe('unchanged')
    expect(keyChangeProblem(form({ password: 'none', keyFile: 'none' }))).toBe('noKey')
    // Keeping a key file the key does not have keeps nothing.
    expect(keyChangeProblem(form({ password: 'none' }))).toBe('noKey')
    expect(keyChangeProblem(form({ now: { password: false, keyFile: true }, password: 'none', keyFile: 'keep' }))).toBe('unchanged')
  })

  it('takes a new password only when typed twice the same', () => {
    expect(keyChangeProblem(form({ password: 'new' }))).toBe('emptyPassword')
    expect(keyChangeProblem(form({ password: 'new', newPassword: 'a', confirm: 'b' }))).toBe('mismatch')
    expect(keyChangeProblem(form({ password: 'new', newPassword: 'a', confirm: 'a' }))).toBeNull()
  })

  it('takes a generated key file only once it is said to be saved', () => {
    expect(keyChangeProblem(form({ keyFile: 'generate' }))).toBe('saveKeyFile')
    expect(keyChangeProblem(form({ keyFile: 'generate', generated: true }))).toBe('saveKeyFile')
    expect(keyChangeProblem(form({ keyFile: 'generate', generated: true, generatedSaved: true }))).toBeNull()
    expect(keyChangeProblem(form({ keyFile: 'choose' }))).toBe('chooseKeyFile')
    expect(keyChangeProblem(form({ keyFile: 'choose', chosen: true }))).toBeNull()
    // The password dropped, a key file alone.
    expect(keyChangeProblem(form({ password: 'none', keyFile: 'choose', chosen: true }))).toBeNull()
  })

  it('offers to keep only what the key has', () => {
    expect(passwordChoices({ password: false, keyFile: true })).toEqual(['none', 'new'])
    expect(keyFileChoices({ password: true, keyFile: false })).toEqual(['none', 'generate', 'choose'])
    expect(keyFileChoices({ password: true, keyFile: true })[0]).toBe('keep')
  })

  it('names the key file as KeePassXC does, without characters a file system refuses', () => {
    expect(keyFileName('Kişisel')).toBe('Kişisel.keyx')
    expect(keyFileName('a/b:c')).toBe('abc.keyx')
    expect(keyFileName('  ')).toBe('vault.keyx')
  })
})
