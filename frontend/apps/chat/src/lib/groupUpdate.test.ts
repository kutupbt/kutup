import { describe, expect, it } from 'vitest'
import { i18n } from '@kutup/i18n'
import '../features/media/testI18n'
import { groupUpdateSentences } from './groupUpdate'

const t = i18n.t.bind(i18n)
const names: Record<string, string> = { 'ali@a.test': 'Ali', 'bob@b.test': 'Bob' }
const nameOf = (address: string) => names[address] ?? address

describe('groupUpdateSentences', () => {
  it('words each change, with the "you" forms for this account', () => {
    expect(
      groupUpdateSentences(
        {
          actor: 'ali@a.test',
          changes: [
            { type: 'nameChanged', name: 'Hikers' },
            { type: 'memberAdded', member: 'bob@b.test' },
            { type: 'memberAdded', member: 'me@a.test' },
            { type: 'descriptionChanged', description: '' },
            { type: 'sendersChanged', administratorsOnly: true },
          ],
        },
        'me@a.test',
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
        { actor: 'me@a.test', changes: [{ type: 'pictureChanged', removed: false }, { type: 'memberLeft', member: 'bob@b.test' }] },
        'me@a.test',
        nameOf,
        t,
      ),
    ).toEqual(['You changed the group picture.', 'Bob left the group.'])
  })
})
