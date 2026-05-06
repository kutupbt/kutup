// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import MnemonicDisplay from './MnemonicDisplay'

const PHRASE_24 =
  'abandon abandon abandon abandon abandon abandon abandon abandon ' +
  'abandon abandon abandon abandon abandon abandon abandon abandon ' +
  'abandon abandon abandon abandon abandon abandon abandon art'

describe('MnemonicDisplay', () => {
  beforeEach(() => {
    // Force the document.execCommand fallback path — it's the simpler one
    // to assert against (no clipboard.writeText spy needed).
    Object.defineProperty(window, 'isSecureContext', { value: false, configurable: true })
    document.execCommand = vi.fn().mockReturnValue(true)
  })

  it('renders all 24 words with 1-based indexing', () => {
    render(<MnemonicDisplay mnemonic={PHRASE_24} />)
    // 23 'abandon' + 1 'art' = 24 word cells.
    expect(screen.getAllByText('abandon')).toHaveLength(23)
    expect(screen.getByText('art')).toBeInTheDocument()
    // The render produces both an index span "1." and a copy/download button
    // — make sure the GRID has them by counting span "1." in the grid only.
    const indexLabels = Array.from(document.querySelectorAll('.font-mono span'))
      .map((el) => el.textContent)
      .filter((t) => /^\d+\.$/.test(t || ''))
    expect(indexLabels).toEqual(
      Array.from({ length: 24 }, (_, i) => `${i + 1}.`),
    )
  })

  it('copy button uses execCommand fallback and flips to "Copied!"', async () => {
    const user = userEvent.setup()
    render(<MnemonicDisplay mnemonic={PHRASE_24} />)
    const buttons = screen.getAllByRole('button')
    const copy = buttons.find((b) => /^copy/i.test(b.textContent || ''))!
    await user.click(copy)
    expect(document.execCommand).toHaveBeenCalledWith('copy')
    expect(await screen.findByText(/copied!/i)).toBeInTheDocument()
  })

  it('download button creates an object URL and triggers a synthetic click', async () => {
    const user = userEvent.setup()
    const createSpy = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:test')
    const revokeSpy = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    render(<MnemonicDisplay mnemonic={PHRASE_24} />)
    const buttons = screen.getAllByRole('button')
    const download = buttons.find((b) => /download/i.test(b.textContent || ''))!
    await user.click(download)

    expect(createSpy).toHaveBeenCalledTimes(1)
    expect(clickSpy).toHaveBeenCalledTimes(1)
    expect(revokeSpy).toHaveBeenCalledTimes(1)

    createSpy.mockRestore()
    revokeSpy.mockRestore()
    clickSpy.mockRestore()
  })

  it('renders short mnemonics with the right number of cells', () => {
    render(<MnemonicDisplay mnemonic="alpha beta gamma" />)
    expect(screen.getByText('alpha')).toBeInTheDocument()
    expect(screen.getByText('beta')).toBeInTheDocument()
    expect(screen.getByText('gamma')).toBeInTheDocument()
    const indexLabels = Array.from(document.querySelectorAll('.font-mono span'))
      .map((el) => el.textContent)
      .filter((t) => /^\d+\.$/.test(t || ''))
    expect(indexLabels).toEqual(['1.', '2.', '3.'])
  })
})
