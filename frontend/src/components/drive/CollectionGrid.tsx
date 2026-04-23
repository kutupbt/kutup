import { Globe, MoreVertical, Info } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Skeleton } from '@/components/ui/skeleton'
import { FolderIcon, FOLDER_COLORS, DEFAULT_FOLDER_COLOR } from './FolderIcon'
import type { Collection } from '@/types/drive'

interface Props {
  collections: Collection[]
  isLoading?: boolean
  currentUserId: string | null
  selectedIds: Set<string>
  onEnter: (col: Collection) => void
  onDetails: (col: Collection) => void
  onToggleSelect: (id: string) => void
  onRename: (col: Collection) => void
  onColor: (col: Collection, color: string | null) => void
  onShare: (col: Collection) => void
  onPublicLink: (col: Collection) => void
  onDelete: (col: Collection) => void
  onRevoke: (col: Collection) => void
  onUploadTo: (col: Collection) => void
  onDrop: (e: React.DragEvent, col: Collection) => void
}

export default function CollectionGrid({
  collections,
  isLoading,
  currentUserId,
  selectedIds,
  onEnter,
  onDetails,
  onToggleSelect,
  onRename,
  onColor,
  onShare,
  onPublicLink,
  onDelete,
  onRevoke,
  onUploadTo,
  onDrop,
}: Props) {
  const { t } = useTranslation()

  if (isLoading) {
    return (
      <div className="flex flex-wrap gap-3 mb-6">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="w-32 h-28 rounded-xl" />
        ))}
      </div>
    )
  }

  if (collections.length === 0) return null

  const anySelected = selectedIds.size > 0

  return (
    <div className={`flex flex-wrap gap-3 mb-6 ${anySelected ? 'selection-active' : ''}`}>
      {collections.map((col) => {
        const isSelected = selectedIds.has(col.id)
        return (
          <div
            key={col.id}
            className={`relative w-32 p-3 bg-card border rounded-xl cursor-pointer select-none transition-colors text-center group ${
              isSelected
                ? 'border-primary bg-primary/5'
                : 'border-border hover:border-primary/50'
            }`}
            onClick={() => onEnter(col)}
            onDragOver={(e) => { e.preventDefault(); e.stopPropagation() }}
            onDrop={(e) => { e.stopPropagation(); onDrop(e, col) }}
          >
            {/* Checkbox — top left, visible on hover or when any selected */}
            <div
              className={`absolute top-1.5 left-1.5 transition-opacity ${
                anySelected || isSelected ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'
              }`}
              onClick={(e) => { e.stopPropagation(); onToggleSelect(col.id) }}
            >
              <Checkbox
                checked={isSelected}
                className="h-5 w-5 bg-background/80 backdrop-blur-sm pointer-events-none"
              />
            </div>

            {/* Dots menu — visible on hover */}
            <div className="absolute top-1.5 right-1.5 opacity-0 group-hover:opacity-100 transition-opacity">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-6 w-6 rounded bg-black/20 hover:bg-black/40 dark:bg-black/40 dark:hover:bg-black/60"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <MoreVertical className="h-3.5 w-3.5" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-48" onClick={(e) => e.stopPropagation()}>
                  <DropdownMenuItem onSelect={() => onDetails(col)}>
                    <Info className="h-4 w-4 mr-2" />
                    {t('folders.details')}
                  </DropdownMenuItem>
                  {!col.isRemote && (
                    <>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem onSelect={() => onRename(col)}>{t('folders.rename')}</DropdownMenuItem>
                      {/* Color picker row */}
                      <div className="flex items-center gap-1.5 px-2 py-1.5">
                        {FOLDER_COLORS.map((fc) => (
                          <button
                            key={fc.value}
                            title={fc.label}
                            className="w-4 h-4 rounded-full border-0 cursor-pointer ring-offset-1 hover:ring-2 ring-white"
                            style={{
                              background: fc.hex,
                              outline: col.color === fc.value ? '2px solid white' : 'none',
                              outlineOffset: 2,
                            }}
                            onClick={(e) => { e.stopPropagation(); onColor(col, fc.value) }}
                          />
                        ))}
                        <button
                          title="Default"
                          className="w-4 h-4 rounded-full border-0 cursor-pointer hover:ring-2 ring-white ring-offset-1"
                          style={{
                            background: DEFAULT_FOLDER_COLOR,
                            outline: !col.color ? '2px solid white' : 'none',
                            outlineOffset: 2,
                          }}
                          onClick={(e) => { e.stopPropagation(); onColor(col, null) }}
                        />
                      </div>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem onSelect={() => onUploadTo(col)}>{t('folders.uploadHere')}</DropdownMenuItem>
                      <DropdownMenuItem onSelect={() => onShare(col)}>{t('folders.share')}</DropdownMenuItem>
                      <DropdownMenuItem onSelect={() => onPublicLink(col)}>{t('folders.copyPublicLink')}</DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        className="text-destructive focus:text-destructive"
                        onSelect={() => onDelete(col)}
                      >
                        {t('folders.deleteFolder')}
                      </DropdownMenuItem>
                    </>
                  )}
                  {col.isRemote && (
                    <>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        className="text-destructive focus:text-destructive"
                        onSelect={() => onRevoke(col)}
                      >
                        {t('folders.removeShare')}
                      </DropdownMenuItem>
                    </>
                  )}
                </DropdownMenuContent>
              </DropdownMenu>
            </div>

            <div className="flex justify-center mt-1">
              <FolderIcon color={col.color} size={56} />
            </div>
            <p className="text-xs text-foreground mt-2 break-words leading-tight">
              {col.isRemote && <Globe className="inline-block h-3 w-3 mr-0.5 text-primary" />}
              {col.decryptedName ?? '…'}
            </p>
          </div>
        )
      })}
    </div>
  )
}
