import { Globe, MoreVertical, Info, Users } from 'lucide-react'
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
import { cn } from '@/lib/utils'
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
      <section className="mb-8">
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-20 rounded-xl" />
          ))}
        </div>
      </section>
    )
  }

  if (collections.length === 0) return null

  const anySelected = selectedIds.size > 0

  return (
    <section className="mb-8">
      <header className="mb-3 flex items-center gap-2">
        <h2 className="text-xs font-semibold tracking-wider text-muted-foreground uppercase">
          Folders
        </h2>
        <span className="text-xs font-medium text-muted-foreground">[{collections.length}]</span>
      </header>

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3">
        {collections.map((col) => {
          const isSelected = selectedIds.has(col.id)
          return (
            <div
              key={col.id}
              className={cn(
                'group relative flex items-center gap-3 px-3 py-3 rounded-xl border bg-card cursor-pointer select-none transition-colors',
                isSelected
                  ? 'border-primary bg-primary/5'
                  : 'border-border hover:border-primary/50 hover:bg-accent/30',
              )}
              onClick={() => onEnter(col)}
              onDragOver={(e) => { e.preventDefault(); e.stopPropagation() }}
              onDrop={(e) => { e.stopPropagation(); onDrop(e, col) }}
            >
              {/* Selection checkbox — shows on hover, persists when any selected */}
              <div
                className={cn(
                  'absolute top-1.5 left-1.5 transition-opacity',
                  anySelected || isSelected ? 'opacity-100' : 'opacity-0 group-hover:opacity-100',
                )}
                onClick={(e) => { e.stopPropagation(); onToggleSelect(col.id) }}
              >
                <Checkbox
                  checked={isSelected}
                  className="h-4 w-4 bg-background/80 backdrop-blur-sm pointer-events-none"
                />
              </div>

              {/* Folder icon */}
              <div className="shrink-0">
                <FolderIcon color={col.color} size={44} />
              </div>

              {/* Name + meta */}
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium leading-snug">
                  {col.decryptedName ?? '…'}
                </p>
                <div className="mt-0.5 flex items-center gap-1.5 text-xs text-muted-foreground">
                  {col.isRemote ? (
                    <>
                      <Globe className="h-3 w-3" />
                      <span>Remote</span>
                    </>
                  ) : col.isShared ? (
                    <>
                      <Users className="h-3 w-3" />
                      <span>Shared</span>
                    </>
                  ) : (
                    <span>Folder</span>
                  )}
                </div>
              </div>

              {/* More menu */}
              <div className="shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <MoreVertical className="h-4 w-4" />
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
            </div>
          )
        })}
      </div>
    </section>
  )
}
