import { describe, expect, it } from 'vitest'
import { i18n } from '@kutup/i18n'
import '../features/media/testI18n'
import { groupUpdateSentences } from './groupUpdate'
import { parseAccount } from '@kutup/chat-core/identity'

const acct = (key: string) => parseAccount(key)!

const t = i18n.t.bind(i18n)
const names: Record<string, string> = { 'aci:00000000-0000-4000-8000-94419b99b12c@a.test': 'Ali', 'aci:00000000-0000-4000-8000-81b637d8fcd2@b.test': 'Bob' }
const nameOf = (address: string) => names[address] ?? address

describe('groupUpdateSentences', () => {
  it('words each change, with the "you" forms for this account', () => {
    expect(
      groupUpdateSentences(
        {
          actor: acct('aci:00000000-0000-4000-8000-94419b99b12c@a.test'),
          changes: [
            { type: 'nameChanged', name: 'Hikers' },
            { type: 'memberAdded', member: acct('aci:00000000-0000-4000-8000-81b637d8fcd2@b.test') },
            { type: 'memberAdded', member: acct('aci:00000000-0000-4000-8000-00000000000e@a.test') },
            { type: 'descriptionChanged', description: '' },
            { type: 'sendersChanged', administratorsOnly: true },
          ],
        },
        'aci:00000000-0000-4000-8000-00000000000e@a.test',
        nameOf,
        t,
      ),
    ).toEqual([
      'Ali changed the group name to “Hikers”.',
      'Ali added Bob.',
      'Ali added you.',
      'Ali removed the group description.',
      'Ali changed who can send messages to administrators only.',
    ])
    expect(
      groupUpdateSentences(
        { actor: acct('aci:00000000-0000-4000-8000-00000000000e@a.test'), changes: [{ type: 'pictureChanged', removed: false }, { type: 'memberLeft', member: acct('aci:00000000-0000-4000-8000-81b637d8fcd2@b.test') }] },
        'aci:00000000-0000-4000-8000-00000000000e@a.test',
        nameOf,
        t,
      ),
    ).toEqual(['You changed the group picture.', 'Bob left the group.'])
  })
})
