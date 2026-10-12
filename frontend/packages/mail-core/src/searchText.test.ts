import { describe, expect, it } from 'vitest'
import { searchText } from './searchText'

describe('searchText', () => {
  it('keeps the subject and the text of HTML, without what is not read', () => {
    const text = searchText('Ekim faturası', {
      html: '<style>.x{color:red}</style><p>Merhaba,</p><div>fatura <b>ektedir</b></div><span style="display: none">gizli</span><script>kod()</script><!-- not -->',
    })
    expect(text).toBe('Ekim faturası\nMerhaba,\nfatura ektedir')
  })

  it('leaves out the quoted earlier message', () => {
    expect(searchText('Re: rapor', { html: '<p>Tamam.</p><blockquote>eski rapor metni</blockquote>' })).toBe('Re: rapor\nTamam.')
    expect(searchText('Re: rapor', { html: '<p>Tamam.</p><div class="gmail_quote">eski</div>' })).toBe('Re: rapor\nTamam.')
    expect(searchText('Re: rapor', { text: 'Tamam.\n\n> eski rapor\n> metni' })).toBe('Re: rapor\nTamam.')
  })

  it('cuts very long messages', () => {
    expect(searchText('', { text: 'a'.repeat(200_000) }).length).toBe(100_000)
  })
})
