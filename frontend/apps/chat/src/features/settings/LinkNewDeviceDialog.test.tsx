import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import '../media/testI18n'

const linkDevice = vi.fn(() => Promise.resolve(true))

vi.mock('../../app/chatStore', () => ({
  useChat: () => ({ service: { linkDevice } }),
}))
vi.mock('../../state/prefs', () => ({
  useReadReceipts: () => true,
  useTypingIndicators: () => false,
}))

const { LinkNewDeviceDialog } = await import('./LinkNewDeviceDialog')

describe('LinkNewDeviceDialog', () => {
  it('sends the identity only after "Link this device?" is confirmed', async () => {
    const onOpenChange = vi.fn()
    render(<LinkNewDeviceDialog open onOpenChange={onOpenChange} />)
    fireEvent.change(screen.getByTestId('chat-link-new-code'), {
      target: { value: 'kutup://link?address=a&key=b' },
    })
    fireEvent.click(screen.getByTestId('chat-link-new-submit'))
    expect(screen.getByText('Link this device?')).toBeVisible()
    expect(linkDevice).not.toHaveBeenCalled()

    fireEvent.click(screen.getByTestId('chat-link-new-confirm'))
    await waitFor(() => {
      expect(linkDevice).toHaveBeenCalledWith('kutup://link?address=a&key=b', {
        readReceipts: true,
        typingIndicators: false,
      })
    })
    await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(false))
  })

  it('sends nothing when the confirmation is cancelled', () => {
    linkDevice.mockClear()
    render(<LinkNewDeviceDialog open onOpenChange={vi.fn()} />)
    fireEvent.change(screen.getByTestId('chat-link-new-code'), {
      target: { value: 'kutup://link?address=a&key=b' },
    })
    fireEvent.click(screen.getByTestId('chat-link-new-submit'))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByText('Link this device?')).toBeNull()
    expect(linkDevice).not.toHaveBeenCalled()
  })
})
