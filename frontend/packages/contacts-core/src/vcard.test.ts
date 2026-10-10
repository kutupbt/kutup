import { describe, expect, it } from 'vitest'
import { displayName, emptyDraft, initials } from './model'
import { parseVCards, toVCard } from './vcard'

describe('vCard', () => {
  it('writes a draft as vCard 4.0 and reads it back', () => {
    const draft = {
      ...emptyDraft(),
      name: 'Ayşe Yılmaz',
      givenName: 'Ayşe',
      familyName: 'Yılmaz',
      emails: [{ address: 'ayse@example.com', label: 'work' }, { address: 'ayse@kutup.dev' }],
      phones: [{ value: '+90 555 000 00 00', label: 'cell' }],
      addresses: [{ street: 'İstiklal Cd. 1', locality: 'İstanbul', region: '', postcode: '34430', country: 'Türkiye', label: 'home' }],
      organization: 'Kutup',
      title: 'Engineer',
      birthday: '--04-23',
      notes: 'Line one\nLine two',
      urls: ['https://kutup.dev'],
    }
    const text = toVCard(draft, 'urn:uuid:1', draft.name)
    expect(text).toMatch(/^BEGIN:VCARD\r\nVERSION:4.0\r\n/)
    const [card] = parseVCards(text)
    expect(card.uid).toBe('urn:uuid:1')
    expect(card.draft).toEqual({ ...draft, photo: '', groups: [] })
  })

  it('reads several vCard 3.0 cards from one file', () => {
    const file = [
      'BEGIN:VCARD', 'VERSION:3.0', 'FN:Ali Veli', 'N:Veli;Ali;;;', 'EMAIL;TYPE=INTERNET,WORK:ali@example.com', 'TEL;TYPE=CELL:+90 1', 'END:VCARD',
      'BEGIN:VCARD', 'VERSION:3.0', 'N:Doe;Jane;;;', 'EMAIL:jane@example.com', 'BDAY:1990-01-02', 'END:VCARD',
    ].join('\r\n')
    const cards = parseVCards(file)
    expect(cards).toHaveLength(2)
    expect(cards[0].draft.emails).toEqual([{ address: 'ali@example.com', label: 'work' }])
    expect(cards[0].draft.phones).toEqual([{ value: '+90 1', label: 'cell' }])
    expect(cards[1].draft.name).toBe('')
    expect(displayName(cards[1].draft)).toBe('Jane Doe')
    expect(cards[1].draft.birthday).toBe('1990-01-02')
  })

  it('makes initials for avatars', () => {
    expect(initials('ayşe yılmaz')).toBe('AY')
    expect(initials('Kutup')).toBe('KU')
    expect(initials('')).toBe('')
  })
})
