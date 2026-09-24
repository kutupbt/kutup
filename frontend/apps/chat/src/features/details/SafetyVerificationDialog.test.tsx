import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import '../media/testI18n'
import type { SafetyNumberV1 } from '@kutup/chat-core/types'
import { SafetyVerificationDialog } from './SafetyVerificationDialog'

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
    const onVerify = vi.fn(() => Promise.resolve(safety('Verified')))
    render(
      <SafetyVerificationDialog
        peer="bob@beta.example"
        safety={safety()}
        onVerify={onVerify}
      />,
    )

    fireEvent.click(screen.getByRole('button', { name: 'Verify bob@beta.example' }))
    expect(screen.getByText(/not verified face to face/i)).toBeVisible()
    expect(screen.getByTestId('chat-safety-qr'))
      .toHaveAttribute('data-value', 'kutup://verify/chat/v1/exact-pair-bound-value')
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
    expect(screen.queryByRole('button', { name: 'Verify exact match' })).toBeNull()
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
    expect(screen.getByText('22'.repeat(32))).toBeVisible()
    expect(screen.getByRole('button', { name: 'Verify exact match' })).toBeDisabled()
  })

  it('can be controlled by a host that owns the trigger', () => {
    const onOpenChange = vi.fn()
    const { rerender } = render(
      <SafetyVerificationDialog
        peer="bob@beta.example"
        safety={safety()}
        onVerify={vi.fn()}
        open={false}
        onOpenChange={onOpenChange}
      />,
    )
    expect(screen.queryByTestId('chat-safety-open')).toBeNull()
    expect(screen.queryByTestId('chat-safety-qr')).toBeNull()

    rerender(
      <SafetyVerificationDialog
        peer="bob@beta.example"
        safety={safety()}
        onVerify={vi.fn()}
        open
        onOpenChange={onOpenChange}
      />,
    )
    expect(screen.getByRole('dialog', { name: 'Verify bob@beta.example' })).toBeVisible()
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    expect(onOpenChange).toHaveBeenCalledWith(false)
  })
})
