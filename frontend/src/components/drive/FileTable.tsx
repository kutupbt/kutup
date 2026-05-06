import { useMemo, useState } from 'react'
import { Download, Trash2, MoreVertical, ArrowUp, ArrowDown, ExternalLink, Info } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from '@/components/ui/context-menu'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Skeleton } from '@/components/ui/skeleton'
import { formatBytes } from '@/lib/format'
import { cn } from '@/lib/utils'
import FileIcon from './FileIcon'
import type { DecryptedFile } from '@/types/drive'

interface Props {
  files: DecryptedFile[]
  isLoading?: boolean
  canDelete: boolean
  selectedIds: Set<string>
  onSelect: (file: DecryptedFile) => void
  onToggleSelect: (id: string) => void
  onToggleSelectAll: () => void
  onDownload: (file: DecryptedFile) => void
  onDelete: (file: DecryptedFile) => void
  onDetails: (file: DecryptedFile) => void
}

type SortKey = 'name' | 'modified' | 'size'
type SortDir = 'asc' | 'desc'

function sortFiles(files: DecryptedFile[], key: SortKey, dir: SortDir): DecryptedFile[] {
  const sign = dir === 'asc' ? 1 : -1
  const out = [...files]
  out.sort((a, b) => {
    switch (key) {
      case 'name':
        return sign * (a.decryptedName ?? '').localeCompare(b.decryptedName ?? '', undefined, { numeric: true })
      case 'modified':
        return sign * (new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime())
      case 'size':
        return sign * ((a.decryptedSize ?? 0) - (b.decryptedSize ?? 0))
    }
  })
  return out
}

function formatModified(iso: string): string {
  const d = new Date(iso)
  const now = new Date()
  const sameYear = d.getFullYear() === now.getFullYear()
  const month = d.toLocaleDateString(undefined, { month: 'short' })
  return sameYear ? `${month} ${d.getDate()}` : `${month} ${d.getDate()}, ${d.getFullYear()}`
}

interface SortableHeadProps {
  label: string
  active: boolean
  dir: SortDir
  onClick: () => void
  className?: string
  align?: 'left' | 'right'
}

function SortableHead({ label, active, dir, onClick, className, align = 'left' }: SortableHeadProps) {
  const Arrow = dir === 'asc' ? ArrowUp : ArrowDown
  return (
    <TableHead className={className}>
      <button
        type="button"
        onClick={onClick}
        className={cn(
          'inline-flex items-center gap-1 font-medium hover:text-foreground transition-colors',
          align === 'right' && 'flex-row-reverse',
          active ? 'text-foreground' : 'text-muted-foreground',
        )}
      >
        {label}
        <Arrow className={cn('h-3.5 w-3.5', !active && 'opacity-0')} />
      </button>
    </TableHead>
  )
}

export default function FileTable({
  files,
  isLoading,
  canDelete,
  selectedIds,
  onSelect,
  onToggleSelect,
  onToggleSelectAll,
  onDownload,
  onDelete,
  onDetails,
}: Props) {
  const { t } = useTranslation()
  const [sortKey, setSortKey] = useState<SortKey>('name')
  const [sortDir, setSortDir] = useState<SortDir>('asc')

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortKey(key)
      setSortDir(key === 'modified' ? 'desc' : 'asc')
    }
  }

  const sorted = useMemo(() => sortFiles(files, sortKey, sortDir), [files, sortKey, sortDir])

  if (isLoading) {
    return (
      <section>
        <div className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-10 w-full" />
          ))}
        </div>
      </section>
    )
  }

  if (files.length === 0) return null

  const allSelected = files.length > 0 && files.every((f) => selectedIds.has(f.id))
  const someSelected = files.some((f) => selectedIds.has(f.id))

  return (
    <section>
      <header className="mb-3 flex items-center gap-2">
        <h2 className="text-xs font-semibold tracking-wider text-muted-foreground uppercase">
          {t('drive.filesHeader')}
        </h2>
        <span className="text-xs font-medium text-muted-foreground">[{files.length}]</span>
      </header>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-12">
              <Checkbox
                checked={allSelected}
                data-state={someSelected && !allSelected ? 'indeterminate' : undefined}
                onCheckedChange={onToggleSelectAll}
                aria-label={t('files.selectAll')}
                className="h-5 w-5"
              />
            </TableHead>
            <SortableHead
              label={t('files.name')}
              active={sortKey === 'name'}
              dir={sortDir}
              onClick={() => toggleSort('name')}
            />
            <SortableHead
              label={t('files.modified')}
              active={sortKey === 'modified'}
              dir={sortDir}
              onClick={() => toggleSort('modified')}
              className="w-32"
            />
            <SortableHead
              label={t('files.size')}
              active={sortKey === 'size'}
              dir={sortDir}
              onClick={() => toggleSort('size')}
              className="w-24"
            />
            <TableHead className="w-12" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {sorted.map((file) => {
            const isSelected = selectedIds.has(file.id)
            return (
              <ContextMenu key={file.id}>
                <ContextMenuTrigger asChild>
                  <TableRow
                    className={cn('group cursor-pointer', isSelected && 'bg-primary/5')}
                    onClick={() => onSelect(file)}
                  >
                    <TableCell
                      className="cursor-pointer"
                      onClick={(e) => { e.stopPropagation(); onToggleSelect(file.id) }}
                    >
                      <Checkbox
                        checked={isSelected}
                        className="h-5 w-5 pointer-events-none"
                      />
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-3 min-w-0">
                        <FileIcon filename={file.decryptedName ?? 'file'} size="sm" />
                        <span className="truncate">
                          {file.decryptedName ?? '[encrypted]'}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {formatModified(file.createdAt)}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {file.decryptedSize ? formatBytes(file.decryptedSize) : '—'}
                    </TableCell>
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7 opacity-0 group-hover:opacity-100 transition-opacity"
                          >
                            <MoreVertical className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onSelect={() => onSelect(file)}>
                            <ExternalLink className="h-4 w-4 mr-2" />
                            {t('common.open')}
                          </DropdownMenuItem>
                          <DropdownMenuItem onSelect={() => onDetails(file)}>
                            <Info className="h-4 w-4 mr-2" />
                            {t('details.title')}
                          </DropdownMenuItem>
                          <DropdownMenuItem onSelect={() => onDownload(file)}>
                            <Download className="h-4 w-4 mr-2" />
                            {t('files.download')}
                          </DropdownMenuItem>
                          {canDelete && (
                            <DropdownMenuItem
                              className="text-destructive focus:text-destructive"
                              onSelect={() => onDelete(file)}
                            >
                              <Trash2 className="h-4 w-4 mr-2" />
                              {t('files.delete')}
                            </DropdownMenuItem>
                          )}
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                </ContextMenuTrigger>
                <ContextMenuContent className="w-44">
                  <ContextMenuItem onSelect={() => onSelect(file)}>
                    <ExternalLink className="h-4 w-4 mr-2" />
                    {t('common.open')}
                  </ContextMenuItem>
                  <ContextMenuItem onSelect={() => onDetails(file)}>
                    <Info className="h-4 w-4 mr-2" />
                    {t('details.title')}
                  </ContextMenuItem>
                  <ContextMenuItem onSelect={() => onDownload(file)}>
                    <Download className="h-4 w-4 mr-2" />
                    {t('files.download')}
                  </ContextMenuItem>
                  {canDelete && (
                    <>
                      <ContextMenuSeparator />
                      <ContextMenuItem
                        className="text-destructive focus:text-destructive"
                        onSelect={() => onDelete(file)}
                      >
                        <Trash2 className="h-4 w-4 mr-2" />
                        {t('files.delete')}
                      </ContextMenuItem>
                    </>
                  )}
                </ContextMenuContent>
              </ContextMenu>
            )
          })}
        </TableBody>
      </Table>
    </section>
  )
}
