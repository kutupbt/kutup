import { forwardRef } from 'react'
import { Search, Upload as UploadIcon, Plus, HelpCircle, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { NewMenuItems, NewMenuActions } from './NewMenu'

interface DriveTopBarProps extends NewMenuActions {
  searchValue: string
  onSearchChange: (v: string) => void
  canUpload: boolean
  onShowHelp: () => void
  newMenuOpen: boolean
  onNewMenuOpenChange: (open: boolean) => void
}

const DriveTopBar = forwardRef<HTMLInputElement, DriveTopBarProps>(function DriveTopBar(
  {
    searchValue,
    onSearchChange,
    canUpload,
    onShowHelp,
    onUpload,
    onNewFolder,
    onNewNote,
    onAddRemote,
    newMenuOpen,
    onNewMenuOpenChange,
  },
  searchRef,
) {
  return (
    <div className="sticky top-0 z-30 flex h-16 items-center gap-3 border-b border-border bg-background/95 backdrop-blur px-6">
      <div className="flex-1" />

      <div className="relative w-full max-w-xl">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none" />
        <Input
          ref={searchRef}
          value={searchValue}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Search in Kutup…"
          className="h-10 pl-9 pr-9 bg-muted/50 border-transparent focus-visible:bg-background"
          aria-label="Search current view"
        />
        {searchValue && (
          <button
            type="button"
            onClick={() => onSearchChange('')}
            aria-label="Clear search"
            className="absolute right-2 top-1/2 -translate-y-1/2 inline-flex h-6 w-6 items-center justify-center rounded text-muted-foreground hover:bg-accent hover:text-foreground"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        )}
      </div>

      <div className="flex-1 flex items-center justify-end gap-2">
        {canUpload && onUpload && (
          <Button onClick={onUpload} className="gap-2">
            <UploadIcon className="h-4 w-4" />
            Upload
          </Button>
        )}

        <DropdownMenu open={newMenuOpen} onOpenChange={onNewMenuOpenChange}>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" className="gap-2">
              <Plus className="h-4 w-4" />
              New
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="min-w-44">
            <NewMenuItems
              onNewFolder={onNewFolder}
              onNewNote={onNewNote}
              onAddRemote={onAddRemote}
              showAddRemote={!!onAddRemote}
            />
          </DropdownMenuContent>
        </DropdownMenu>

        <Button
          variant="ghost"
          size="icon"
          onClick={onShowHelp}
          aria-label="Keyboard shortcuts"
          title="Keyboard shortcuts (?)"
        >
          <HelpCircle className="h-5 w-5" />
        </Button>
      </div>
    </div>
  )
})

export default DriveTopBar
