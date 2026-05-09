import { Download, Trash2, Pencil, Share2, Globe, Link2, FileText } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { FolderIcon, FOLDER_COLORS, DEFAULT_FOLDER_COLOR } from './FolderIcon'
import { formatBytes } from '@/lib/format'
import type { Collection, DecryptedFile } from '@/types/drive'

function isCollection(item: Collection | DecryptedFile): item is Collection {
  return 'ownerUserId' in item
}

interface Props {
  item: Collection | DecryptedFile | null
  canDelete: boolean
  onClose: () => void
  onDownload?: (file: DecryptedFile) => void
  onDownloadFolder?: (col: Collection) => void
  onDelete?: (item: Collection | DecryptedFile) => void
  onRename?: (col: Collection) => void
  onRenameFile?: (file: DecryptedFile) => void
  onColor?: (col: Collection, color: string | null) => void
  onShare?: (col: Collection) => void
  onPublicLink?: (col: Collection) => void
  onEnter?: (col: Collection) => void
}

export default function DetailsPanel({
  item,
  canDelete,
  onClose,
  onDownload,
  onDownloadFolder,
  onDelete,
  onRename,
  onRenameFile,
  onColor,
  onShare,
  onPublicLink,
  onEnter,
}: Props) {
  const { t } = useTranslation()

  if (!item) return null

  const isFolder = isCollection(item)

  const showColorRow = isFolder && !(item as Collection).isRemote && !!onColor

  // One-line centered meta strip. Files show "size · date"; remote folders
  // show a federation badge; owned folders have nothing here (color row
  // below carries their meta).
  const metaParts: React.ReactNode[] = []
  if (!isFolder) {
    const f = item as DecryptedFile
    if (f.decryptedSize != null) metaParts.push(formatBytes(f.decryptedSize))
    if (f.createdAt) metaParts.push(new Date(f.createdAt).toLocaleDateString())
  } else if ((item as Collection).isRemote) {
    metaParts.push(
      <span key="fed" className="inline-flex items-center gap-1">
        <Globe className="h-3 w-3 text-primary" />
        {t('details.federatedShare')}
      </span>,
    )
  }

  const hasMetaText = metaParts.length > 0
  const hasMeta = hasMetaText || showColorRow

  return (
    <Dialog open={!!item} onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent className="sm:max-w-sm flex flex-col">
        <DialogHeader className="pb-2">
          <DialogTitle>{t('details.title')}</DialogTitle>
        </DialogHeader>

        {/* Icon + name */}
        <div className="flex flex-col items-center gap-3 py-6">
          {isFolder ? (
            <FolderIcon color={(item as Collection).color} size={72} />
          ) : (
            <div className="w-16 h-16 flex items-center justify-center rounded-2xl bg-muted">
              <FileText className="h-8 w-8 text-muted-foreground" />
            </div>
          )}
          <p className="text-sm font-medium text-center break-all px-2">
            {isFolder
              ? (item as Collection).decryptedName ?? '…'
              : (item as DecryptedFile).decryptedName ?? '[encrypted]'}
          </p>
        </div>

        {hasMeta && (
          <>
            <Separator />
            <div className="py-4 flex flex-col items-center gap-3">
              {hasMetaText && (
                <p className="text-xs text-muted-foreground flex items-center gap-2">
                  {metaParts.map((part, i) => (
                    <span key={i} className="inline-flex items-center gap-2">
                      {i > 0 && <span aria-hidden>·</span>}
                      {part}
                    </span>
                  ))}
                </p>
              )}
              {showColorRow && onColor && (
                <div className="flex items-center justify-center gap-2">
                  {FOLDER_COLORS.map((fc) => (
                    <button
                      key={fc.value}
                      type="button"
                      title={fc.label}
                      aria-label={`Set color to ${fc.label}`}
                      className="h-6 w-6 rounded-full transition-transform hover:scale-110"
                      style={{
                        background: fc.hex,
                        outline: (item as Collection).color === fc.value ? '2px solid var(--ring)' : 'none',
                        outlineOffset: 2,
                      }}
                      onClick={() => onColor(item as Collection, fc.value)}
                    />
                  ))}
                  <button
                    type="button"
                    title="Default"
                    aria-label="Reset to default color"
                    className="h-6 w-6 rounded-full transition-transform hover:scale-110"
                    style={{
                      background: DEFAULT_FOLDER_COLOR,
                      outline: !(item as Collection).color ? '2px solid var(--ring)' : 'none',
                      outlineOffset: 2,
                    }}
                    onClick={() => onColor(item as Collection, null)}
                  />
                </div>
              )}
            </div>
          </>
        )}

        <Separator />

        {/* Actions */}
        <div className="flex flex-col gap-2 pt-4 flex-1">
          {isFolder ? (
            <>
              <Button className="w-full" onClick={() => { onEnter?.(item as Collection); onClose() }}>
                {t('details.openFolder')}
              </Button>
              <Button variant="outline" className="w-full" onClick={() => { onDownloadFolder?.(item as Collection); onClose() }}>
                <Download className="h-4 w-4 mr-2" /> {t('details.downloadFolder')}
              </Button>
              {!(item as Collection).isRemote && (
                <>
                  <Button variant="outline" className="w-full" onClick={() => { onRename?.(item as Collection); onClose() }}>
                    <Pencil className="h-4 w-4 mr-2" /> {t('details.rename')}
                  </Button>
                  <Button variant="outline" className="w-full" onClick={() => { onShare?.(item as Collection); onClose() }}>
                    <Share2 className="h-4 w-4 mr-2" /> {t('details.share')}
                  </Button>
                  <Button variant="outline" className="w-full" onClick={() => { onPublicLink?.(item as Collection); onClose() }}>
                    <Link2 className="h-4 w-4 mr-2" /> {t('details.copyPublicLink')}
                  </Button>
                </>
              )}
              {canDelete && (
                <Button
                  variant="destructive"
                  className="w-full mt-auto"
                  onClick={() => { onDelete?.(item); onClose() }}
                >
                  <Trash2 className="h-4 w-4 mr-2" /> {t('details.deleteFolder')}
                </Button>
              )}
            </>
          ) : (
            <>
              <Button className="w-full" onClick={() => onDownload?.(item as DecryptedFile)}>
                <Download className="h-4 w-4 mr-2" /> {t('details.download')}
              </Button>
              {canDelete && onRenameFile && (
                <Button
                  variant="outline"
                  className="w-full"
                  onClick={() => { onRenameFile(item as DecryptedFile); onClose() }}
                >
                  <Pencil className="h-4 w-4 mr-2" /> {t('details.rename')}
                </Button>
              )}
              {canDelete && (
                <Button
                  variant="destructive"
                  className="w-full mt-auto"
                  onClick={() => { onDelete?.(item); onClose() }}
                >
                  <Trash2 className="h-4 w-4 mr-2" /> {t('details.delete')}
                </Button>
              )}
            </>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
