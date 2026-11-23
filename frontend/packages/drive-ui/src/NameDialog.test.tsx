// @vitest-environment jsdom
import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { NameDialog } from './NameDialog'

vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string) => key }) }))

function renderDialog(creating: boolean) {
  const onSubmit = vi.fn()
  const onClose = vi.fn()
  render(
    <NameDialog
      open
      title="Name"
      initial="Untitled folder"
      submit="Save"
      pending={false}
      error={null}
      creating={creating}
      onClose={onClose}
      onSubmit={onSubmit}
    />,
  )
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  return { onSubmit, onClose }
}

describe('NameDialog', () => {
  it('makes something new under the suggested name when it is left as is', () => {
    const { onSubmit, onClose } = renderDialog(true)
    expect(onSubmit).toHaveBeenCalledWith('Untitled folder')
    expect(onClose).not.toHaveBeenCalled()
  })

  it('only closes a rename left unchanged', () => {
    const { onSubmit, onClose } = renderDialog(false)
    expect(onSubmit).not.toHaveBeenCalled()
    expect(onClose).toHaveBeenCalled()
  })
})
