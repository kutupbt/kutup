import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import './testI18n'

const mutate = vi.fn()
vi.mock('@kutup/mail-core/filters', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@kutup/mail-core/filters')>()),
  useCreateFilter: () => ({ mutate, isPending: false }),
  useUpdateFilter: () => ({ mutate: vi.fn(), isPending: false }),
  useApplyFilters: () => ({ mutate: vi.fn() }),
  useFilters: () => ({ data: [] }),
}))
vi.mock('@kutup/mail-core/places', () => ({
  usePlaces: () => ({ data: { tree: [], labels: [] } }),
  flattenFolders: () => [],
}))
vi.mock('sonner', () => ({ toast: Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn() }) }))

const { FilterDialog } = await import('./FilterDialog')

describe('the filter wizard', () => {
  it('saves a new filter once, with one id, however fast Save is pressed', () => {
    render(<FilterDialog onClose={() => undefined} />)
    fireEvent.change(screen.getByLabelText('Filter name'), { target: { value: 'Faturalar' } })
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    fireEvent.change(screen.getByLabelText('Value'), { target: { value: 'FATURA' } })
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'Starred' }))
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    const save = screen.getByRole('button', { name: 'Save' })
    // Both before React has seen the first request as pending.
    fireEvent.click(save)
    fireEvent.click(save)
    expect(mutate).toHaveBeenCalledTimes(1)
    const [draft] = mutate.mock.calls[0] as [{ id: string; name: string }]
    expect(draft.name).toBe('Faturalar')
    expect(draft.id).toMatch(/^[0-9a-f-]{36}$/)
  })
})
