import { useTranslation } from 'react-i18next'
import { BottomSheet } from '@/components/ui/bottom-sheet'
import { SheetAction } from '@/components/ui/sheet-action'
import { FolderSVG } from '@/components/mobile/FolderSVG'
import { FileTypeIcon } from '@/components/mobile/FileTypeIcon'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { formatBytes } from '@/lib/format'
import { formatDateLong } from '@/components/mobile/dateFormat'
import { FOLDER_COLORS, folderHex } from '@/components/drive/FolderIcon'
import type { Collection, DecryptedFile } from '@/types/drive'
import { cn } from '@/lib/utils'

/**
 * MobileItemSheet — the design's `ItemDetailsSheet` ported into kutup.
 *
 * Opens when the user taps the ⋯ button on a folder tile or file row in
 * `MobileFilesPage`. Shows a preview header (icon + name + secondary
 * metadata + E2E badge) and an action list:
 *
 *   Folder: Open / Color / Download as ZIP / Share / Rename / Move to Trash
 *   File:   Open / Download / Share / Rename / Move to Trash
 *
 * The Color row is folder-only and renders the 5 desktop color swatches
 * inline (same `FOLDER_COLORS` table the desktop CollectionGrid uses);
 * tapping a swatch calls `onChangeColor` and closes the sheet.
 *
 * Action wiring: each handler is optional. Sheet rows for unwired actions
 * are hidden so PR 2's partial backing (e.g. no Share dialog on mobile yet)
 * doesn't surface dead buttons.
 */

export interface MobileItemSheetProps {
  item: Collection | DecryptedFile | null
  onClose: () => void
  /** Open the folder (navigate into) or the file (preview / editor). */
  onOpen?: (item: Collection | DecryptedFile) => void
  onRename?: (item: Collection | DecryptedFile) => void
  onShare?: (item: Collection) => void
  onDownload?: (file: DecryptedFile) => void
  onDelete?: (item: Collection | DecryptedFile) => void
  /** Folder-only: pick a color from the desktop's FOLDER_COLORS palette. */
  onChangeColor?: (folder: Collection, color: string | null) => void
}

/** Discriminate between Collection and DecryptedFile — kutup's Collection
 *  has `encryptedName` (no `encryptedMetadata`) and File has the reverse. */
function isFolder(item: Collection | DecryptedFile): item is Collection {
  return 'encryptedName' in item
}

export function MobileItemSheet({
  item,
  onClose,
  onOpen,
  onRename,
  onShare,
  onDownload,
  onDelete,
  onChangeColor,
}: MobileItemSheetProps) {
  const { t } = useTranslation()
  if (!item) return null

  const folder = isFolder(item) ? item : null
  const file = isFolder(item) ? null : item

  return (
    <BottomSheet open={!!item} onOpenChange={(open) => !open && onClose()}>
      {/* Preview header */}
      <div className="flex flex-col items-center gap-2.5 px-4 pt-3 pb-5 border-b border-border-light">
        {folder ? (
          <FolderSVG color={folder.color} size={64} />
        ) : (
          <FileTypeIcon mime={file?.decryptedMimeType} size={64} />
        )}
        <div className="text-center max-w-full">
          <div className="text-[15px] font-semibold text-text-primary break-all">
            {folder?.decryptedName ?? file?.decryptedName ?? '—'}
          </div>
          <div className="text-[12px] text-text-tertiary mt-0.5">
            {folder
              ? folder.isShared
                ? t('mobile.item.sharedFolder', 'Shared folder')
                : t('mobile.item.folder', 'Folder')
              : `${formatBytes(file?.decryptedSize ?? 0)} · ${formatDateLong(file?.createdAt)}`}
          </div>
        </div>
        {/* E2E badge */}
        <div className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-success-faint rounded-[12px]">
          <Icon d={ICONS.lock} size={11} color="var(--success)" />
          <span className="text-[11px] text-success font-semibold">
            {t('mobile.item.e2eBadge', 'End-to-end encrypted')}
          </span>
        </div>
      </div>

      {/* Actions */}
      <div>
        {onOpen && (
          <SheetAction
            icon={folder ? 'folder' : 'download'}
            label={folder ? t('mobile.item.open', 'Open') : t('mobile.item.open', 'Open')}
            variant="primary"
            onClick={() => {
              onOpen(item)
              onClose()
            }}
          />
        )}

        {folder && onChangeColor && (
          <FolderColorRow
            current={folder.color}
            onPick={(color) => {
              onChangeColor(folder, color)
              onClose()
            }}
          />
        )}

        {file && onDownload && (
          <SheetAction
            icon="download"
            label={t('mobile.item.download', 'Download')}
            onClick={() => {
              onDownload(file)
              onClose()
            }}
          />
        )}

        {folder && onShare && (
          <SheetAction
            icon="share"
            label={t('mobile.item.share', 'Share')}
            onClick={() => {
              onShare(folder)
              onClose()
            }}
          />
        )}

        {onRename && (
          <SheetAction
            icon="rename"
            label={t('mobile.item.rename', 'Rename')}
            onClick={() => {
              onRename(item)
              onClose()
            }}
          />
        )}

        {onDelete && (
          <SheetAction
            icon="trash"
            label={t('mobile.item.trash', 'Move to Trash')}
            variant="danger"
            onClick={() => {
              onDelete(item)
              onClose()
            }}
            last
          />
        )}
      </div>
    </BottomSheet>
  )
}

/** Inline folder-color picker — five round swatches + an "× clear" reset.
 *  Reuses the desktop `FOLDER_COLORS` table so values stay in sync. */
function FolderColorRow({
  current,
  onPick,
}: {
  current: string | null
  onPick: (color: string | null) => void
}) {
  const { t } = useTranslation()
  return (
    <div className="border-b border-border-light px-4 py-3.5 flex items-center gap-3.5">
      <div className="w-8 h-8 rounded-2xl bg-surface-sunken text-text-secondary flex items-center justify-center shrink-0">
        <Icon d={ICONS.star} size={16} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium text-text-primary">
          {t('mobile.item.color', 'Color')}
        </div>
        <div className="mt-2 flex items-center gap-2">
          {FOLDER_COLORS.map((c) => {
            const active = current === c.value
            return (
              <button
                key={c.value}
                type="button"
                aria-label={c.label}
                title={c.label}
                onClick={() => onPick(c.value)}
                style={{ background: c.hex }}
                className={cn(
                  'h-7 w-7 rounded-full border-2 transition-transform',
                  active ? 'border-foreground' : 'border-transparent',
                  'active:scale-95',
                )}
              />
            )
          })}
          <button
            type="button"
            aria-label={t('mobile.item.colorClear', 'Clear color')}
            title={t('mobile.item.colorClear', 'Clear color')}
            onClick={() => onPick(null)}
            style={{ background: folderHex(null), opacity: current === null ? 1 : 0.4 }}
            className={cn(
              'h-7 w-7 rounded-full border-2 transition-transform',
              current === null ? 'border-foreground' : 'border-transparent',
              'active:scale-95 flex items-center justify-center text-white',
            )}
          >
            <Icon d={ICONS.x} size={12} color="white" />
          </button>
        </div>
      </div>
    </div>
  )
}
