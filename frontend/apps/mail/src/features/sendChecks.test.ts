import { describe, expect, it } from 'vitest'
import { isNoReplyAddress, mentionedAttachment, ownWords } from './sendChecks'

describe('the checks before a send (Proton)', () => {
  it('knows no-reply addresses as Proton does', () => {
    for (const address of ['noreply@shop.test', 'no-reply@shop.test', 'No_Reply@shop.test', 'do.not.reply@bank.test', 'donotreply+x@bank.test', 'alerts-noreply@x.test']) {
      expect(isNoReplyAddress(address), address).toBe(true)
    }
    for (const address of ['reply@x.test', 'nora@x.test', 'support@noreply.test']) {
      expect(isNoReplyAddress(address), address).toBe(false)
    }
  })

  it('finds an attachment mentioned in English or Turkish', () => {
    expect(mentionedAttachment('Hi, please find attached the report.')).toBe('find attached')
    expect(mentionedAttachment('I have\n attached it')).toBe('I have attached')
    expect(mentionedAttachment('Raporu ekte bulabilirsiniz.')).toBe('ekte')
    expect(mentionedAttachment('Dosyayı EKLEDİM, bakar mısın?')).toBe('dosyayı ekledim')
    expect(mentionedAttachment('Bunu dikkate alalım.')).toBeNull()
    expect(mentionedAttachment('Nothing to see here.')).toBeNull()
  })

  it('reads only what the sender wrote: no quote, no signature', () => {
    const signature = '<p>— Ayşe, see attached CV on my site</p>'
    const html = `<p>Thanks!</p><p></p>${signature}<p>On Monday Bob wrote:</p><blockquote><p>I have attached the file</p></blockquote>`
    expect(mentionedAttachment(ownWords({ html }, signature))).toBeNull()
    expect(ownWords({ html: '<p>See attached.</p>' })).toBe('See attached.')
    expect(mentionedAttachment(ownWords({ plain: 'Thanks\n> see attached\n>> find attached' }))).toBeNull()
    expect(mentionedAttachment(ownWords({ plain: 'see attached\n> old' }))).toBe('see attached')
  })
})
