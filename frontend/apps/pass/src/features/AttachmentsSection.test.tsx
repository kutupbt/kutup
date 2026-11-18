import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import '../testI18n'
import type { VaultSession } from '../sync/vaultSession'
import type { EntryView } from '../vault/types'
import { previewKind } from '../lib/attachmentPreview'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))
const { AttachmentsSection } = await import('./AttachmentsSection')

const entry = { id: 'e1', inRecycleBin: false, attachments: [{ name: 'notes.txt', size: 30 }, { name: 'id.pem', size: 3 }] } as unknown as EntryView
const sessionWith = (files: Record<string, string>) =>
  ({ vault: () => ({ attachment: (_: string, name: string) => Promise.resolve(new TextEncoder().encode(files[name])) }) }) as unknown as VaultSession

describe('attachments', () => {
  it('previews images and text by name, nothing else', () => {
    expect(previewKind('photo.JPG')).toBe('image')
    expect(previewKind('key.pem')).toBe('text')
    expect(previewKind('report.pdf')).toBeNull()
    expect(previewKind('archive.zip')).toBeNull()
    expect(previewKind('.bashrc')).toBeNull()
  })

  it('shows a text file as text, never as markup', async () => {
    const run = vi.fn(() => Promise.resolve(true))
    render(<AttachmentsSection entry={entry} session={sessionWith({ 'notes.txt': '<b id="x">bold</b>' })} canEdit run={run} />)
    fireEvent.click(screen.getByRole('button', { name: 'Preview notes.txt' }))
    const preview = await screen.findByTestId('attachment-preview')
    await waitFor(() => expect(preview.textContent).toContain('<b id="x">bold</b>'))
    expect(document.getElementById('x')).toBeNull()
  })

  it('asks once for the clashing names of several files, and skips them when told', async () => {
    const run = vi.fn((_op: unknown) => Promise.resolve(true))
    render(<AttachmentsSection entry={entry} session={sessionWith({})} canEdit run={run} />)
    // jsdom's File has no arrayBuffer().
    const file = (body: string, name: string) => Object.assign(new File([body], name), { arrayBuffer: () => Promise.resolve(new TextEncoder().encode(body).buffer) })
    const files = [file('a', 'id.pem'), file('b', 'new.txt'), file('c', 'notes.txt')]
    fireEvent.change(screen.getByTestId('attachment-input'), { target: { files } })
    expect(await screen.findByRole('dialog', { name: 'Replace 2 attachments?' })).toBeTruthy()
    expect(run).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Skip these' }))
    await waitFor(() => expect(run).toHaveBeenCalledTimes(1))
    expect(run.mock.calls[0][0]).toMatchObject({ op: 'addAttachment', entryId: 'e1', name: 'new.txt' })
  })

  it('renames, refusing a name the entry has', async () => {
    const run = vi.fn((_op: unknown, _done?: string) => Promise.resolve(true))
    render(<AttachmentsSection entry={entry} session={sessionWith({})} canEdit run={run} />)
    fireEvent.click(screen.getByRole('button', { name: 'Rename notes.txt' }))
    const name = await screen.findByLabelText('Name')
    fireEvent.change(name, { target: { value: 'id.pem' } })
    expect(screen.getByText('This entry already has an attachment with that name.')).toBeTruthy()
    expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Rename' }).disabled).toBe(true)
    fireEvent.change(name, { target: { value: ' todo.txt ' } })
    fireEvent.click(screen.getByRole('button', { name: 'Rename' }))
    await waitFor(() => expect(run).toHaveBeenCalledWith({ op: 'renameAttachment', entryId: 'e1', name: 'notes.txt', newName: 'todo.txt' }, 'Attachment renamed'))
  })
})
