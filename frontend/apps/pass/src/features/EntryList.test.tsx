import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import '../testI18n'
import type { VaultSession } from '../sync/vaultSession'
import type { EntryView, VaultView } from '../vault/types'

vi.mock('./SiteIcon', () => ({ SiteIcon: () => null }))
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))
const { EntryList } = await import('./EntryList')

const entry = (id: string, title: string) =>
  ({ id, groupId: 'root', inRecycleBin: false, fields: [{ key: 'Title', value: title, protected: false }], tags: [], review: [] }) as unknown as EntryView
const view = (recycleBinEnabled: boolean) =>
  ({ rootGroupId: 'root', recycleBinId: 'bin', recycleBinEnabled, groups: [], entries: [] }) as unknown as VaultView

// The bar's delete asks first; what it does is what the dialog asked, never
// what the vault says by the time it is confirmed (docs/plans/pass-parity.md).
describe('the entry list', () => {
  it("recycles as asked even if the bin went off before the confirm, and never deletes for good", async () => {
    const apply = vi.fn(() => Promise.reject(new Error('the recycle bin is off')))
    // The vault as the session holds it now: the bin was turned off.
    const session = { canEdit: true, apply, getState: () => ({ view: view(false) }) } as unknown as VaultSession
    const shown = [entry('a', 'A1'), entry('b', 'A2')]
    const props = { session, shown, currentId: undefined, viewingBin: false, pictures: new Map<string, string>(), onOpen: () => undefined }
    const { rerender } = render(<EntryList {...props} view={view(true)} />)
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select A1' }))
    fireEvent.click(screen.getByRole('button', { name: 'Move to recycle bin' }))
    expect(await screen.findByRole('alertdialog', { name: 'Move 1 entry to the recycle bin?' })).toBeTruthy()

    // Another device's save turns the bin off while the dialog is open.
    rerender(<EntryList {...props} view={view(false)} />)
    fireEvent.click(screen.getByRole('alertdialog').querySelector('button[type="submit"], button:last-of-type') as HTMLElement)

    await waitFor(() => expect(apply).toHaveBeenCalledTimes(1))
    expect(apply).toHaveBeenCalledWith({ op: 'recycleEntries', ids: ['a'] })
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('The recycle bin was turned off; nothing was deleted.'))
    expect(toast.success).not.toHaveBeenCalled()
  })

  it('says a failed recycle is a failed save when the bin is still on', async () => {
    const apply = vi.fn(() => Promise.reject(new Error('offline')))
    const session = { canEdit: true, apply, getState: () => ({ view: view(true) }) } as unknown as VaultSession
    toast.error.mockClear()
    render(<EntryList session={session} view={view(true)} shown={[entry('c', 'A3')]} currentId={undefined} viewingBin={false} pictures={new Map<string, string>()} onOpen={() => undefined} />)
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select A3' }))
    fireEvent.click(screen.getByRole('button', { name: 'Move to recycle bin' }))
    await screen.findByRole('alertdialog', { name: 'Move 1 entry to the recycle bin?' })
    fireEvent.click(screen.getByRole('alertdialog').querySelector('button[type="submit"], button:last-of-type') as HTMLElement)
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('The change could not be made.'))
  })
})
