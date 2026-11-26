import { describe, expect, it } from 'vitest'
import * as files from '@kutup/drive-core/files'
import * as folders from '@kutup/drive-core/folders'
import * as mutations from '@kutup/drive-core/mutations'
import * as trash from '@kutup/drive-core/trash'
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
})
