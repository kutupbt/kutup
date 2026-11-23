import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import '../testI18n'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
const { PasskeyCard } = await import('./PasskeyCard')

describe('the passkey card', () => {
  it('shows the site, user and credential, and says the key stays in the vault', () => {
    const { container } = render(<PasskeyCard passkey={{ relyingParty: 'github.com', username: 'ayse', credentialId: 'Y3JlZA', userHandle: 'dXNlcg', hasPrivateKey: true }} />)
    expect(screen.getByText('github.com')).toBeTruthy()
    expect(screen.getByText('ayse')).toBeTruthy()
    expect(screen.getByText('Y3JlZA')).toBeTruthy()
    expect(screen.getByText(/stays in the vault and is never shown/)).toBeTruthy()
    // Nothing of a key, not even hidden: no PEM text, no hidden or secret input.
    expect(container.innerHTML).not.toMatch(/PRIVATE KEY|BEGIN/)
    expect(container.querySelectorAll('input, textarea, [hidden], [aria-hidden="true"]:not(svg)')).toHaveLength(0)
  })
})
