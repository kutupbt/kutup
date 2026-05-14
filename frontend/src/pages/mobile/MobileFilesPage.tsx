import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { FolderSVG } from '@/components/mobile/FolderSVG'
import { FileTypeIcon } from '@/components/mobile/FileTypeIcon'
import { MobilePageHeader } from '@/components/mobile/MobilePageHeader'
import { MobileSearchInput } from '@/components/mobile/MobileSearchInput'
import { IconButton } from '@/components/ui/icon-button'
import { Surface } from '@/components/ui/surface'
import { SectionLabel } from '@/components/ui/section-label'
import { PressableRow } from '@/components/ui/pressable-row'
import { StorageCard } from '@/components/ui/storage-card'
import { EmptyState } from '@/components/ui/empty-state'
import { BottomSheet } from '@/components/ui/bottom-sheet'
import { SheetAction } from '@/components/ui/sheet-action'
import { formatBytes } from '@/lib/format'
import { formatDateShort, formatDateLong } from '@/components/mobile/dateFormat'
import type { Collection, DecryptedFile } from '@/types/drive'
import type { FolderColorName } from '@/components/mobile/FolderSVG'
import { cn } from '@/lib/utils'

/**
 * MobileFilesPage — direct port of the design's Files screen.
 *
 * Renders the existing Drive data (folders + files at the current level) with
 * the design's visual language: large title, storage card on root, category
 * chips, 2-col folder grid + file list, search slide-in, and a FAB-in-header
 * that opens an "Add to Kutup" bottom sheet.
 *
 * Driven by props from `Drive.tsx` so its rich state (selection, breadcrumb
 * stack, upload pipeline, dialogs) stays the source of truth — no data
 * duplication. PR 2 ships the visuals + a working FAB sheet that delegates to
 * the existing dialog handlers; the chip filters are visual-only and get
 * wired in PR 3.
 */

interface MobileFilesPageProps {
  folders: Collection[]
  files: DecryptedFile[]
  currentFolder: Collection | null
  /** True when `currentFolder` is the user's root "My Files" collection (or
   *  unset). Drives the large-title pattern + suppresses the Back button at
   *  the top level. In kutup the root Collection is non-null (unlike the
   *  design prototype), so this must be derived in `Drive.tsx` rather than
   *  inferred from `currentFolder == null`. */
  isAtRoot: boolean
  /** Total bytes used by this user. */
  usedBytes: number
  /** Storage quota in bytes. */
  quotaBytes: number
  onOpenFolder: (folder: Collection) => void
  onOpenFile: (file: DecryptedFile) => void
  onBack: () => void
  /** Show item-action sheet for a folder or file. */
  onItemMore: (item: Collection | DecryptedFile) => void
  /** Add-sheet actions. */
  onUploadFiles: () => void
  onUploadFolder: () => void
  onNewFolder: () => void
  onNewNote: () => void
  onNewWhiteboard: () => void
  /** Optional remote-share intake (PR 3+: paste encrypted link). */
  onPasteEncryptedLink?: () => void
}

const CHIPS = [
  { id: 'all', key: 'mobile.files.chips.all' as const, fallback: 'All' },
  { id: 'recent', key: 'mobile.files.chips.recent' as const, fallback: 'Recent' },
  { id: 'photos', key: 'mobile.files.chips.photos' as const, fallback: 'Photos' },
  { id: 'documents', key: 'mobile.files.chips.documents' as const, fallback: 'Documents' },
  { id: 'pdfs', key: 'mobile.files.chips.pdfs' as const, fallback: 'PDFs' },
  { id: 'audio', key: 'mobile.files.chips.audio' as const, fallback: 'Audio' },
] as const

export function MobileFilesPage(props: MobileFilesPageProps) {
  const {
    folders,
    files,
    currentFolder,
    isAtRoot,
    usedBytes,
    quotaBytes,
    onOpenFolder,
    onOpenFile,
    onBack,
    onItemMore,
    onUploadFiles,
    onUploadFolder,
    onNewFolder,
    onNewNote,
    onNewWhiteboard,
    onPasteEncryptedLink,
  } = props
  const { t } = useTranslation()

  const [search, setSearch] = useState('')
  const [searchOpen, setSearchOpen] = useState(false)
  const [addOpen, setAddOpen] = useState(false)
  const [activeChip, setActiveChip] = useState<typeof CHIPS[number]['id']>('all')

  const filteredFolders = useMemo(() => {
    if (!search) return folders
    const q = search.toLowerCase()
    return folders.filter((f) => (f.decryptedName ?? '').toLowerCase().includes(q))
  }, [folders, search])

  const filteredFiles = useMemo(() => {
    if (!search) return files
    const q = search.toLowerCase()
    return files.filter((f) => (f.decryptedName ?? '').toLowerCase().includes(q))
  }, [files, search])

  const isEmpty = filteredFolders.length === 0 && filteredFiles.length === 0
  const showLargeTitle = isAtRoot && !searchOpen

  // At root we show the section label ("My Files"); inside a sub-folder we
  // show the folder's decrypted name.
  const titleText = isAtRoot
    ? t('nav.files', 'Files')
    : currentFolder?.decryptedName ?? ''
  const subtitleText = showLargeTitle
    ? t('mobile.files.subtitle', '{{folders}} folders · {{files}} files', {
        folders: folders.length,
        files: files.length,
      })
    : undefined

  return (
    <>
      <MobilePageHeader
        title={titleText}
        subtitle={subtitleText}
        large={showLargeTitle}
        back={!isAtRoot}
        onBack={onBack}
        right={
          searchOpen ? null : (
            <>
              <IconButton
                icon="search"
                onClick={() => setSearchOpen(true)}
                ariaLabel={t('mobile.files.search.placeholder', 'Search in Kutup…')}
              />
              <IconButton
                icon="plus"
                onClick={() => setAddOpen(true)}
                accent
                ariaLabel={t('mobile.sheet.add.title', 'Add to Kutup')}
              />
            </>
          )
        }
      />

      {searchOpen && (
        <MobileSearchInput
          value={search}
          onChange={setSearch}
          onCancel={() => {
            setSearch('')
            setSearchOpen(false)
          }}
          autoFocus
        />
      )}

      <div className="flex-1 overflow-auto px-3.5 pt-3 pb-24">
        {isAtRoot && !searchOpen && (
          <div className="mb-4">
            <StorageCard used={usedBytes} quota={quotaBytes} />
          </div>
        )}

        {isAtRoot && !searchOpen && (
          <div className="-mx-3.5 px-3.5 mb-4 flex gap-2 overflow-x-auto pb-1">
            {CHIPS.map((c) => {
              const active = activeChip === c.id
              return (
                <button
                  key={c.id}
                  type="button"
                  onClick={() => setActiveChip(c.id)}
                  className={cn(
                    'shrink-0 px-3.5 py-1.5 rounded-2xl text-[12.5px] font-medium cursor-pointer border transition-colors',
                    active
                      ? 'bg-primary text-white border-primary'
                      : 'bg-surface text-text-secondary border-border hover:bg-surface-raised',
                  )}
                >
                  {t(c.key, c.fallback)}
                </button>
              )
            })}
          </div>
        )}

        {isEmpty && search && (
          <EmptyState
            icon="search"
            title={t('mobile.files.search.empty', 'No results for "{{q}}"', { q: search })}
            subtitle={t('mobile.files.empty.subtitle', 'Try a different search term')}
            tint="muted"
          />
        )}

        {filteredFolders.length > 0 && (
          <div className="mb-5">
            <SectionLabel>
              {t('mobile.section.folders', 'Folders · {{n}}', { n: filteredFolders.length })}
            </SectionLabel>
            <div className="grid grid-cols-2 gap-2.5">
              {filteredFolders.map((folder) => (
                <FolderTile
                  key={folder.id}
                  folder={folder}
                  onOpen={onOpenFolder}
                  onMore={onItemMore}
                />
              ))}
            </div>
          </div>
        )}

        {filteredFiles.length > 0 && (
          <div>
            <SectionLabel>
              {t('mobile.section.files', 'Files · {{n}}', { n: filteredFiles.length })}
            </SectionLabel>
            <Surface>
              {filteredFiles.map((file, i) => (
                <FileListRow
                  key={file.id}
                  file={file}
                  onOpen={onOpenFile}
                  onMore={onItemMore}
                  last={i === filteredFiles.length - 1}
                />
              ))}
            </Surface>
          </div>
        )}
      </div>

      {/* Add sheet (FAB-in-header) */}
      <BottomSheet
        open={addOpen}
        onOpenChange={setAddOpen}
        title={t('mobile.sheet.add.title', 'Add to Kutup')}
      >
        <SheetAction
          icon="upload"
          label={t('mobile.sheet.add.upload', 'Upload files')}
          sub={t('mobile.sheet.add.uploadSub', 'From your device')}
          onClick={() => {
            setAddOpen(false)
            onUploadFiles()
          }}
          variant="primary"
        />
        <SheetAction
          icon="folderPlus"
          label={t('mobile.sheet.add.uploadFolder', 'Upload folder')}
          onClick={() => {
            setAddOpen(false)
            onUploadFolder()
          }}
        />
        <SheetAction
          icon="folderPlus"
          label={t('mobile.sheet.add.newFolder', 'New folder')}
          onClick={() => {
            setAddOpen(false)
            onNewFolder()
          }}
        />
        <SheetAction
          icon="rename"
          label={t('mobile.sheet.add.newNote', 'New note')}
          onClick={() => {
            setAddOpen(false)
            onNewNote()
          }}
        />
        <SheetAction
          icon="star"
          label={t('mobile.sheet.add.newWhiteboard', 'New whiteboard')}
          onClick={() => {
            setAddOpen(false)
            onNewWhiteboard()
          }}
        />
        {onPasteEncryptedLink && (
          <SheetAction
            icon="key"
            label={t('mobile.sheet.add.pasteLink', 'Paste encrypted link')}
            sub={t('mobile.sheet.add.pasteLinkSub', 'Decrypt a shared file')}
            onClick={() => {
              setAddOpen(false)
              onPasteEncryptedLink()
            }}
            last
          />
        )}
      </BottomSheet>
    </>
  )
}

/** Internal: a single folder tile in the 2-col grid. */
function FolderTile({
  folder,
  onOpen,
  onMore,
}: {
  folder: Collection
  onOpen: (f: Collection) => void
  onMore: (f: Collection) => void
}) {
  const [pressed, setPressed] = useState(false)
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onOpen(folder)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          onOpen(folder)
        }
      }}
      onTouchStart={() => setPressed(true)}
      onTouchEnd={() => setPressed(false)}
      onMouseDown={() => setPressed(true)}
      onMouseUp={() => setPressed(false)}
      onMouseLeave={() => setPressed(false)}
      className={cn(
        'relative p-3 border border-border-light rounded-[var(--radius-lg)]',
        'cursor-pointer select-none transition-colors flex flex-col gap-2',
        pressed ? 'bg-surface-raised' : 'bg-surface',
      )}
    >
      <div className="flex items-start justify-between">
        <FolderSVG color={folder.color as FolderColorName} size={40} />
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation()
            onMore(folder)
          }}
          aria-label="More actions"
          className="w-7 h-7 rounded-[14px] border-0 bg-transparent cursor-pointer text-text-tertiary flex items-center justify-center -mr-1 -mt-1"
        >
          <Icon d={ICONS.more} size={16} />
        </button>
      </div>
      <div className="min-w-0">
        <div className="text-[13.5px] font-semibold text-text-primary flex items-center gap-1 truncate">
          {folder.isRemote && (
            <Icon d={ICONS.globe} size={11} color="var(--primary)" style={{ flexShrink: 0 }} />
          )}
          <span className="truncate">{folder.decryptedName ?? '...'}</span>
        </div>
        <div className="text-[11.5px] text-text-tertiary mt-0.5 flex items-center gap-1">
          {folder.isShared && <Icon d={ICONS.users} size={10} />}
        </div>
      </div>
    </div>
  )
}

/** Internal: a single file row inside the surface. */
function FileListRow({
  file,
  onOpen,
  onMore,
  last,
}: {
  file: DecryptedFile
  onOpen: (f: DecryptedFile) => void
  onMore: (f: DecryptedFile) => void
  last: boolean
}) {
  return (
    <PressableRow onClick={() => onOpen(file)} last={last} ariaLabel={file.decryptedName ?? ''}>
      <FileTypeIcon mime={file.decryptedMimeType} size={40} />
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium text-text-primary truncate">
          {file.decryptedName ?? '—'}
        </div>
        <div className="text-[12px] text-text-tertiary mt-0.5">
          {formatDateShort(file.createdAt)} · {formatBytes(file.decryptedSize ?? 0)}
        </div>
      </div>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation()
          onMore(file)
        }}
        aria-label="More actions"
        className="w-8 h-8 rounded-2xl border-0 bg-transparent cursor-pointer text-text-tertiary flex items-center justify-center"
      >
        <Icon d={ICONS.more} size={16} />
      </button>
    </PressableRow>
  )
}

// Re-export for tests / external usage.
export { formatDateLong }
