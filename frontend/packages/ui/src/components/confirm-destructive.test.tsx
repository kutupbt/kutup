import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ConfirmDestructive } from './confirm-destructive'

describe('ConfirmDestructive with a password', () => {
  it('hands the password over once and keeps no copy, so a failed attempt asks again', () => {
    const onConfirm = vi.fn()
    const view = render(
      <ConfirmDestructive
        open
        onOpenChange={() => {}}
        title="Wipe account"
        description="Starts it over."
        submit="Wipe account"
        errorFallback="Failed"
        passwordLabel="Your own password"
        onConfirm={onConfirm}
      />,
    )
    const field = screen.getByLabelText('Your own password')
    fireEvent.change(field, { target: { value: 'admin-secret' } })
    fireEvent.click(screen.getByRole('button', { name: 'Wipe account' }))
    expect(onConfirm).toHaveBeenCalledWith('admin-secret')
    expect((field as HTMLInputElement).value).toBe('')
    // The attempt failed: the error shows, and the field is still empty.
    view.rerender(
      <ConfirmDestructive
        open
        onOpenChange={() => {}}
        title="Wipe account"
        description="Starts it over."
        submit="Wipe account"
        error={new Error('wrong')}
        errorFallback="Failed"
        passwordLabel="Your own password"
        onConfirm={onConfirm}
      />,
    )
    const again = screen.getByLabelText('Your own password')
    const button = screen.getByRole('button', { name: 'Wipe account' })
    if (!(again instanceof HTMLInputElement) || !(button instanceof HTMLButtonElement)) throw new Error('unexpected elements')
    expect(again.value).toBe('')
    expect(button.disabled).toBe(true)
  })
})
