import { render, screen, waitFor } from '@testing-library/react'
import { useState } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from './dialog'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from './dropdown-menu'

function MenuInDialog({ onOpenChange }: { onOpenChange: (open: boolean) => void }) {
  const [open, setOpen] = useState(true)
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        onOpenChange(next)
        setOpen(next)
      }}
    >
      <DialogContent>
        <DialogTitle>Share</DialogTitle>
        <DialogDescription>People with access</DialogDescription>
        <DropdownMenu>
          <DropdownMenuTrigger>Role</DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem>Can view</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </DialogContent>
    </Dialog>
  )
}

function key(target: Element, value: string) {
  target.dispatchEvent(new KeyboardEvent('keydown', { key: value, bubbles: true, cancelable: true }))
}

describe('Dialog with a menu inside', () => {
  // The race needs React's real scheduling: inside act() every queued render
  // runs before the next event, and the bug disappears.
  const act = globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }
  let previous: boolean | undefined
  beforeEach(() => {
    previous = act.IS_REACT_ACT_ENVIRONMENT
    act.IS_REACT_ACT_ENVIRONMENT = false
  })
  afterEach(() => {
    act.IS_REACT_ACT_ENVIRONMENT = previous
  })

  it('an Escape right after the menu opens closes the menu, not the dialog', async () => {
    const onOpenChange = vi.fn()
    render(<MenuInDialog onOpenChange={onOpenChange} />)
    const trigger = await screen.findByRole('button', { name: 'Role' })

    // Open the menu and press Escape before the layers re-render to learn
    // the menu is now on top. React commits the open in a microtask and the
    // re-render in a later task; under load a browser delivers a key press in
    // that gap (input runs before scheduled renders), and the dialog used to
    // take the Escape and close with the menu inside it.
    key(trigger, 'Enter')
    await Promise.resolve()
    expect(document.querySelector('[role="menu"]')).not.toBeNull()
    key(document.activeElement ?? document.body, 'Escape')

    await waitFor(() => expect(screen.queryByRole('menu')).toBeNull())
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(onOpenChange).not.toHaveBeenCalled()

    // With the menu gone, Escape belongs to the dialog again.
    key(document.activeElement ?? document.body, 'Escape')
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(onOpenChange).toHaveBeenCalledWith(false)
  })
})
