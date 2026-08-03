import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { SafetyVerificationDialog } from './SafetyVerificationDialog'
import type { SafetyNumberV1 } from './types'

function safety(trust: SafetyNumberV1['trust'] = 'Tofu'): SafetyNumberV1 {
  return {
    localAccount: 'alice@alpha.example',
    peerAccount: 'bob@beta.example',
    fingerprint: Array.from({ length: 16 }, (_, index) => String(index).padStart(5, '0')).join(' '),
    qrPayload: 'kutup://verify/chat/v1/exact-pair-bound-value',
    authorityKeyId: '11'.repeat(32),
    trust,
    continuityGap: false,
    retainedAuthorityKeyId: undefined,
    quarantineReason: undefined,
  }
}

describe('SafetyVerificationDialog', () => {
  it('shows gray TOFU state and submits only the captured peer QR value', async () => {
    const onVerify = vi.fn(async () => safety('Verified'))
    render(
      <SafetyVerificationDialog
        peer="bob@beta.example"
        safety={safety()}
        onVerify={onVerify}
      />,
    )

    fireEvent.click(screen.getByRole('button', { name: 'Verify bob@beta.example' }))
    expect(screen.getByText(/not verified face to face/i)).toBeVisible()
    expect(screen.getByTestId('chat-safety-number')).toHaveTextContent('00000 00001')
    fireEvent.change(screen.getByPlaceholderText('kutup://verify/chat/v1/…'), {
      target: { value: 'kutup://verify/chat/v1/scanned-from-bob' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Verify exact match' }))

    await waitFor(() => {
      expect(onVerify).toHaveBeenCalledWith('kutup://verify/chat/v1/scanned-from-bob')
    })
  })

  it('renders verified and continuity-warning states distinctly', () => {
    const { rerender } = render(
      <SafetyVerificationDialog
        peer="bob@beta.example"
        safety={safety('Verified')}
        onVerify={vi.fn()}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'bob@beta.example is verified' }))
    expect(screen.getByText(/verified face to face/i)).toBeVisible()
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))

    rerender(
      <SafetyVerificationDialog
        peer="bob@beta.example"
        safety={{ ...safety(), trust: 'Quarantined', retainedAuthorityKeyId: '22'.repeat(32) }}
        onVerify={vi.fn()}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Security warning for bob@beta.example' }))
    expect(screen.getByText(/sending remains blocked/i)).toBeVisible()
    expect(screen.getByRole('button', { name: 'Verify exact match' })).toBeDisabled()
  })
})
