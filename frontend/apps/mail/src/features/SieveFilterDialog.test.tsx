import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { MailFilter } from '@kutup/mail-core/filters'
import './testI18n'

const create = vi.fn()
const update = vi.fn()
vi.mock('@kutup/mail-core/filters', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@kutup/mail-core/filters')>()),
  useCreateFilter: () => ({ mutate: create, isPending: false }),
  useUpdateFilter: () => ({ mutate: update, isPending: false }),
  useFilters: () => ({ data: [{ id: 'other', name: 'Taken' }] }),
}))
vi.mock('@kutup/mail-core/places', () => ({
  usePlaces: () => ({
    isSuccess: true,
    data: { folders: new Map([['f1', { id: 'f1', name: 'Work', parentId: null }]]), labels: [{ id: 'l1', name: 'Bills' }] },
  }),
}))
vi.mock('sonner', () => ({ toast: Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn() }) }))
// The CodeMirror editor is loaded on demand; here a plain text area stands in.
vi.mock('./SieveEditor', () => ({
  default: ({ value, onChange, label }: { value: string; onChange: (v: string) => void; label: string }) => (
    <textarea aria-label={label} defaultValue={value} onChange={(e) => onChange(e.target.value)} />
  ),
}))

const { SieveFilterDialog } = await import('./SieveFilterDialog')

const RULE = `require ["fileinto", "imap4flags"];
if allof (header :comparator "i;unicode-casemap" :contains "Subject" "invoice")
{
    fileinto "Work";
    fileinto "Bills";
    addflag "\\\\Flagged";
}
`

async function script(): Promise<HTMLTextAreaElement> {
  return screen.findByLabelText<HTMLTextAreaElement>('Sieve script')
}

describe('a filter written as Sieve', () => {
  beforeEach(() => {
    create.mockReset()
    update.mockReset()
  })

  it('starts from the template, and saves the one filter a script holds', async () => {
    render(<SieveFilterDialog onClose={() => undefined} />)
    const editor = await script()
    expect(editor.value.startsWith('require ["fileinto", "imap4flags"];')).toBe(true)
    const save = screen.getByRole('button', { name: 'Save' })
    await waitFor(() => expect(screen.getByTestId('sieve-filter-problems').textContent).toMatch(/no filter/i))
    expect(save).toBeDisabled()

    fireEvent.change(editor, { target: { value: RULE } })
    await waitFor(() => expect(save).toBeEnabled())
    // A name is needed, and one not taken.
    fireEvent.click(save)
    expect(create).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText('Filter name'), { target: { value: 'taken ' } })
    fireEvent.click(save)
    expect(create).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText('Filter name'), { target: { value: 'Invoices' } })
    fireEvent.click(save)
    expect(create).toHaveBeenCalledTimes(1)
    const [draft] = create.mock.calls[0] as [{ id: string; name: string; match: string; conditions: unknown; actions: unknown }]
    expect(draft).toMatchObject({
      name: 'Invoices',
      match: 'all',
      conditions: [{ field: 'subject', op: 'contains', negate: false, value: 'invoice' }],
      actions: { folder: 'custom:f1', labels: ['l1'], star: true },
    })
    expect(draft.id).toMatch(/^[0-9a-f-]{36}$/)
  })

  it('opens a filter as its script and saves it back to the same filter', async () => {
    const filter: MailFilter = {
      id: 'f-1',
      name: 'Clients',
      nameRevision: 1,
      enabled: false,
      position: 3,
      match: 'any',
      conditions: [{ field: 'sender', op: 'ends', negate: false, value: '@client.test' }],
      actions: { folder: 'archive', markRead: true },
      source: 'manual',
    }
    render(<SieveFilterDialog filter={filter} onClose={() => undefined} />)
    const editor = await script()
    expect(editor.value).toContain(':matches "From" "*@client.test"')
    expect(editor.value).toContain('fileinto "archive";')
    const save = screen.getByRole('button', { name: 'Save' })
    await waitFor(() => expect(save).toBeEnabled())
    fireEvent.click(save)
    expect(update).toHaveBeenCalledTimes(1)
    expect(update.mock.calls[0][0]).toMatchObject({ id: 'f-1', name: 'Clients', match: 'any', actions: { folder: 'archive', markRead: true } })
  })

  it('refuses what Kutup filters cannot do, and points to where Kutup does it', async () => {
    render(<SieveFilterDialog onClose={() => undefined} />)
    fireEvent.change(await script(), { target: { value: 'require ["vacation"];\nvacation "away";\n' } })
    await waitFor(() => expect(screen.getByTestId('sieve-filter-problems').textContent).toContain('Auto-reply'))
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('holds one filter: two if blocks are refused', async () => {
    render(<SieveFilterDialog onClose={() => undefined} />)
    fireEvent.change(await script(), { target: { value: `${RULE}\nif header :is "Subject" "x" { addflag "\\\\Seen"; }\n` } })
    await waitFor(() => expect(screen.getByTestId('sieve-filter-problems').textContent).toMatch(/one filter/i))
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('asks before throwing away changes, and not when there are none', async () => {
    const onClose = vi.fn()
    const { unmount } = render(<SieveFilterDialog onClose={onClose} />)
    await script()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onClose).toHaveBeenCalledTimes(1)
    unmount()

    onClose.mockReset()
    render(<SieveFilterDialog onClose={onClose} />)
    fireEvent.change(await script(), { target: { value: RULE } })
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onClose).not.toHaveBeenCalled()
    expect(await screen.findByText('Discard your changes?')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Discard' }))
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})
