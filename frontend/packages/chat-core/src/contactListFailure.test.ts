import { describe, expect, it } from 'vitest'
import { contactListFailure } from './service'

describe('a held mailbox says why', () => {
  it('is its own failure, and an integrity one when the server contradicts the verified state', () => {
    expect(contactListFailure(new Error('contact list unconfirmed: transport: network error'))?.code).toBe('contactListUnconfirmed')
    expect(contactListFailure(new Error("contact list unconfirmed: transport: chatContacts: the server's list does not match the account's verified state"))?.code).toBe(
      'contactListIntegrity',
    )
    expect(contactListFailure(new Error('contact list unconfirmed: device trust: contact list: an entry is not the revision listed'))?.code).toBe('contactListIntegrity')
    expect(contactListFailure(new Error("contact list unconfirmed: transport: the account's history on the server is not the one this app knows (rollback)"))?.code).toBe(
      'contactListIntegrity',
    )
  })

  it('leaves every other failure alone', () => {
    expect(contactListFailure(new Error('transport: offline'))).toBeNull()
  })
})
