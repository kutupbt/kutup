import { describe, expect, it } from 'vitest'
import { VaultError } from './client'

describe('VaultError', () => {
  it('says why an open failed from its first word, and nothing for any other message', () => {
    expect(new VaultError('wrongKey: the vault could not be opened').failure).toBe('wrongKey')
    expect(new VaultError('unsupported: Unsupported database version').failure).toBe('unsupported')
    expect(new VaultError('damaged: Unexpected end of file').failure).toBe('damaged')
    expect(new VaultError('this vault is read-only for you').failure).toBeNull()
    expect(new VaultError('constructor: nope').failure).toBeNull()
  })
})
