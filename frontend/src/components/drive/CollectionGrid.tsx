import { Globe, MoreVertical } from 'lucide-react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { FolderIcon, FOLDER_COLORS, DEFAULT_FOLDER_COLOR } from './FolderIcon'
import type { Collection } from '@/types/drive'

interface Props {
  collections: Collection[]
  isLoading?: boolean
  currentUserId: string | null
  onEnter: (col: Collection) => void
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
  onEnter,
  onRename,
  onColor,
  onShare,
  onPublicLink,
  onDelete,
  onRevoke,
  onUploadTo,
  onDrop,
}: Props) {
  if (isLoading) {
    return (
      <div className="flex flex-wrap gap-3 mb-6">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="w-28 h-24 rounded-xl" />
        ))}
      </div>
    )
  }

  if (collections.length === 0) return null

  return (
    <div className="flex flex-wrap gap-3 mb-6">
      {collections.map((col) => (
        <div
          key={col.id}
          className="relative w-28 p-3 bg-card border border-border rounded-xl cursor-pointer select-none hover:border-primary/50 transition-colors text-center group"
          onClick={() => onEnter(col)}
          onDragOver={(e) => { e.preventDefault(); e.stopPropagation() }}
          onDrop={(e) => { e.stopPropagation(); onDrop(e, col) }}
        >
          {/* Dots menu — visible on hover */}
          <div className="absolute top-1.5 right-1.5 opacity-0 group-hover:opacity-100 transition-opacity">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-6 w-6 rounded bg-black/40 hover:bg-black/60"
                  onClick={(e) => e.stopPropagation()}
                >
                  <MoreVertical className="h-3.5 w-3.5" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-48" onClick={(e) => e.stopPropagation()}>
                {!col.isRemote && (
                  <>
                    <DropdownMenuItem onSelect={() => onRename(col)}>Rename</DropdownMenuItem>
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
                    <DropdownMenuItem onSelect={() => onUploadTo(col)}>Upload here</DropdownMenuItem>
                    <DropdownMenuItem onSelect={() => onShare(col)}>Share</DropdownMenuItem>
                    <DropdownMenuItem onSelect={() => onPublicLink(col)}>Copy public link</DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem
                      className="text-destructive focus:text-destructive"
                      onSelect={() => onDelete(col)}
                    >
                      Delete folder
                    </DropdownMenuItem>
                  </>
                )}
                {col.isRemote && (
                  <DropdownMenuItem
                    className="text-destructive focus:text-destructive"
                    onSelect={() => onRevoke(col)}
                  >
                    Remove share
                  </DropdownMenuItem>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          </div>

          <FolderIcon color={col.color} size={44} />
          <p className="text-xs text-muted-foreground mt-2 break-words leading-tight">
            {col.isRemote && <Globe className="inline-block h-3 w-3 mr-0.5 text-primary" />}
            {col.decryptedName ?? '…'}
          </p>
        </div>
      ))}
    </div>
  )
}
