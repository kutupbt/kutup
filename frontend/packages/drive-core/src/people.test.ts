import { describe, expect, it } from 'vitest'
import { personOf, personOfAccount, type People } from './people'

const ada = { server: 'kutup.dev', accountId: '00000000-0000-4000-8000-000000000001' }
const adaKey = 'aci:00000000-0000-4000-8000-000000000001@kutup.dev'

const people: People = {
  byAccount: new Map([[adaKey, { displayName: 'Ada Lovelace' }]]),
  accountAt: new Map([['ada_l@kutup.dev', adaKey]]),
}

describe('people by account', () => {
  it('shows an account by its own profile, found by account or by the address it has now', () => {
    expect(personOfAccount(people, ada, 'ada_l@kutup.dev').name).toBe('Ada Lovelace')
    expect(personOf(people, 'Ada_L@kutup.dev').name).toBe('Ada Lovelace')
  })

  it('shows an address no account has now as itself, never as the profile it had before', () => {
    expect(personOf(people, 'ada@kutup.dev')).toEqual({ name: 'ada@kutup.dev', profile: null })
    expect(personOfAccount(people, { ...ada, accountId: '00000000-0000-4000-8000-000000000002' }, 'x@kutup.dev').name).toBe('x@kutup.dev')
    expect(personOfAccount(undefined, ada, 'ada_l@kutup.dev').name).toBe('ada_l@kutup.dev')
  })
})
