import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import '../testI18n'
import type { VaultSession } from '../sync/vaultSession'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
const { PropertiesSection } = await import('./PropertiesSection')

describe('properties', () => {
  it('shows the UUID as hex and the custom data, read when opened', async () => {
    const customData = vi.fn(() =>
      Promise.resolve([
        { key: 'KPXC_DECRYPTION_TIME_PREFERENCE', value: '1000', bytes: 4, modified: null },
        { key: 'blob', value: null, bytes: 2048, modified: null },
      ]),
    )
    const session = { vault: () => ({ customData }) } as unknown as VaultSession
    render(<PropertiesSection session={session} id="0F8FAD5B-D9CB-469F-A165-70867728950E" created={null} modified={null} />)
    expect(customData).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Properties' }))
    expect(screen.getByText('0f8fad5bd9cb469fa16570867728950e')).toBeTruthy()
    await waitFor(() => expect(screen.getAllByTestId('custom-data-row')).toHaveLength(2))
    expect(customData).toHaveBeenCalledWith('0F8FAD5B-D9CB-469F-A165-70867728950E')
    expect(screen.getByText('KPXC_DECRYPTION_TIME_PREFERENCE')).toBeTruthy()
    expect(screen.getByText(/^Binary, /)).toBeTruthy()
    // Read-only: nothing to edit or remove.
    expect(screen.queryByRole('textbox')).toBeNull()
  })
})
