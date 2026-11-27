import { act, render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { ItemRef, PublicLinkAction } from '@kutup/drive-source/source'

type Callbacks = { onSuccess?: (url: string) => void; onError?: (error: unknown) => void; onSettled?: () => void }
const mutate = vi.hoisted(() => vi.fn<(folder: unknown, callbacks: Callbacks) => void>())
const toastError = vi.hoisted(() => vi.fn())

vi.mock('@kutup/drive-core/mutations', () => ({ useCreatePublicLink: () => ({ mutate }) }))
vi.mock('sonner', () => ({ toast: { error: toastError, success: vi.fn() } }))
vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string) => key }) }))

const { useKutupPublicLink } = await import('./publicLink')

// The folder as the screen passes it: a new object on every render, and another
// after the folder's key is rotated (the re-key of spec 226), as the folder list
// is fetched again.
const folder = (version: number) => ({ id: 'f1', name: 'Photos', canManage: true, keyVersion: version }) as unknown as ItemRef['folder']

let action: PublicLinkAction
// A screen that renders again with each new version of the folder, as FolderPage does.
function Screen({ version }: { version: number }): ReactNode {
  action = useKutupPublicLink()
  return <div data-version={version}>{action.dialog}</div>
}

describe('useKutupPublicLink', () => {
  beforeEach(() => {
    mutate.mockReset()
    toastError.mockReset()
  })

  it('makes no link while rendering, however often the screen renders', () => {
    const { rerender } = render(<Screen version={1} />)
    for (let i = 0; i < 20; i++) rerender(<Screen version={1 + (i % 3)} />)
    expect(mutate).not.toHaveBeenCalled()
  })

  it('opening the link dialog makes one link, and re-renders or a re-key make no more', () => {
    const { rerender } = render(<Screen version={1} />)
    act(() => action.create({ folder: folder(1) }))
    expect(mutate).toHaveBeenCalledTimes(1)
    act(() => mutate.mock.calls[0][1].onSuccess?.('https://drive.example/s/abc'))
    act(() => mutate.mock.calls[0][1].onSettled?.())
    // The dialog is open with the link; the folder is re-keyed and refetched.
    for (let i = 0; i < 20; i++) rerender(<Screen version={2 + i} />)
    expect(mutate).toHaveBeenCalledTimes(1)
    expect(screen.getAllByDisplayValue('https://drive.example/s/abc')).toHaveLength(1)
  })

  it('a second click before the first link is back makes no second link', () => {
    render(<Screen version={1} />)
    act(() => {
      action.create({ folder: folder(1) })
      action.create({ folder: folder(1) })
    })
    expect(mutate).toHaveBeenCalledTimes(1)
    // Once it is back, the next click is a new link, as it was before.
    act(() => mutate.mock.calls[0][1].onSettled?.())
    act(() => action.create({ folder: folder(1) }))
    expect(mutate).toHaveBeenCalledTimes(2)
  })

  it('a link that cannot be made shows a toast and no dialog', () => {
    render(<Screen version={1} />)
    act(() => action.create({ folder: folder(1) }))
    act(() => {
      mutate.mock.calls[0][1].onError?.(new Error('no'))
      mutate.mock.calls[0][1].onSettled?.()
    })
    expect(toastError).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})
