import { describe, expect, it } from 'vitest'
import { parseInvite } from './mutations'

const capability = 'A'.repeat(43)

describe('parseInvite', () => {
  it('reads server and capability from the fragment', () => {
    expect(parseInvite(`https://drive.a.example/invite#server=a.example&capability=${capability}`)).toEqual({
      server: 'a.example',
      capability,
    })
    expect(parseInvite(`  https://a.example/invite/#server=a.example&capability=${capability} `)).not.toBeNull()
  })

  it('refuses anything that is not an invite', () => {
    expect(parseInvite('not a url')).toBeNull()
    expect(parseInvite(`https://a.example/other#server=a.example&capability=${capability}`)).toBeNull()
    expect(parseInvite(`https://a.example/invite#server=localhost&capability=${capability}`)).toBeNull()
    expect(parseInvite('https://a.example/invite#server=a.example&capability=short')).toBeNull()
    // The capability belongs in the fragment, never the query the server would log.
    expect(parseInvite(`https://a.example/invite?server=a.example&capability=${capability}`)).toBeNull()
  })
})
