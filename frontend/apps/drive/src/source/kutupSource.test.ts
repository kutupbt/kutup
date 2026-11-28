import type { UseMutationResult } from '@tanstack/react-query'
import { describe, expect, it } from 'vitest'
import * as fileShares from '@kutup/drive-core/fileShares'
import * as files from '@kutup/drive-core/files'
import * as folders from '@kutup/drive-core/folders'
import type { Folder } from '@kutup/drive-core/model'
import * as mutations from '@kutup/drive-core/mutations'
import * as sharedByMe from '@kutup/drive-core/sharedByMe'
import * as trash from '@kutup/drive-core/trash'
import type { DriveSource } from '@kutup/drive-source/source'
import * as driveIndex from '@kutup/editors/driveIndex'
import * as copy from './kutup/drive/useCopy'
import * as move from './kutup/drive/useMove'
import * as versions from './kutup/versions'
import { kutupDriveSource } from './kutupSource'

// The editors, Calendar's attachments and the upload commit invalidate Drive's
// lists by drive-core's query keys: Kutup's source must be drive-core's own
// hooks, not copies with keys of their own.
describe('kutupDriveSource', () => {
  it('is drive-core, hook for hook', () => {
    const s = kutupDriveSource
    expect(s.useFolders).toBe(folders.useFolders)
    expect(s.useFolderFiles).toBe(files.useFolderFiles)
    expect(s.useTrash).toBe(trash.useTrash)
    expect(s.useCreateFolder).toBe(mutations.useCreateFolder)
    expect(s.useRenameFolder).toBe(mutations.useRenameFolder)
    expect(s.useRenameFile).toBe(mutations.useRenameFile)
    expect(s.useSetFolderColor).toBe(mutations.useSetFolderColor)
    expect(s.useTrashFolder).toBe(mutations.useTrashFolder)
    expect(s.useTrashFile).toBe(mutations.useTrashFile)
    expect(s.useRestore).toBe(trash.useRestore)
    expect(s.usePurge).toBe(trash.usePurge)
    expect(s.useEmptyTrash).toBe(trash.useEmptyTrash)
  })

  // Every other hook that owns a query key, or invalidates drive-core's: pinned as it is today, so
  // a change that wraps one shows up here.
  it('passes the sharing, search, copy, move, leave and version hooks straight through', () => {
    const s = kutupDriveSource
    expect(s.useSharedByMe).toBe(sharedByMe.useSharedByMe)
    expect(s.useSharedFiles).toBe(fileShares.useSharedFiles)
    expect(s.useSearchIndex).toBe(driveIndex.useDriveIndex)
    expect(s.useCopy).toBe(copy.useCopy)
    expect(s.useMove).toBe(move.useMove)
    expect(s.useLeaveFolder).toBe(mutations.useLeaveRemoteShare)
    expect(s.useLeaveFile).toBe(fileShares.useLeaveRemoteFileShare)
    expect(s.useVersionHistory).toBe(versions.useKutupVersionHistory)
  })
})

// kutupSource gives drive-core's hooks to the interface with a plain `as` (they take Kutup's
// objects where the interface takes views). TypeScript allows that only between related types:
// if drive-core's hook and the interface drift apart, the cast stops compiling. Each line below is
// such a drift and must be refused by tsc (an unused @ts-expect-error fails the build).
describe('the casts in kutupSource are checked', () => {
  it('refuses a hook whose result or argument no longer matches the interface', () => {
    const otherResult = null as unknown as () => UseMutationResult<number, Error, { parent: Folder; name: string }>
    // @ts-expect-error the new folder's id is a string, not a number
    void (otherResult as DriveSource['useCreateFolder'])
    const otherArgument = null as unknown as () => UseMutationResult<string, Error, { parent: number; name: string }>
    // @ts-expect-error the parent is a folder, not a number
    void (otherArgument as DriveSource['useCreateFolder'])
    const otherFunction = null as unknown as () => (tree: number) => Promise<void>
    // @ts-expect-error copying takes the folder tree, the items and the destination
    void (otherFunction as DriveSource['useCopy'])
    expect(otherResult).toBeNull()
  })
})
