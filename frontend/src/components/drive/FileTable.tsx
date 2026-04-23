import { Download, Trash2, MoreVertical, FileText } from 'lucide-react'
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
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Skeleton } from '@/components/ui/skeleton'
import { formatBytes } from '@/lib/format'
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
}: Props) {
  const { t } = useTranslation()

  if (isLoading) {
    return (
      <div className="space-y-2 mt-2">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    )
  }

  if (files.length === 0) return null

  const allSelected = files.length > 0 && files.every((f) => selectedIds.has(f.id))
  const someSelected = files.some((f) => selectedIds.has(f.id))

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="w-12">
            <Checkbox
              checked={allSelected}
              data-state={someSelected && !allSelected ? 'indeterminate' : undefined}
              onCheckedChange={onToggleSelectAll}
              aria-label="Select all files"
              className="h-5 w-5"
            />
          </TableHead>
          <TableHead>{t('files.name')}</TableHead>
          <TableHead className="w-24">{t('files.size')}</TableHead>
          <TableHead className="w-32">{t('files.uploaded')}</TableHead>
          <TableHead className="w-12" />
        </TableRow>
      </TableHeader>
      <TableBody>
        {files.map((file) => {
          const isSelected = selectedIds.has(file.id)
          return (
            <TableRow
              key={file.id}
              className={`group cursor-pointer ${isSelected ? 'bg-primary/5' : ''}`}
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
                <div className="flex items-center gap-2">
                  <FileText className="h-4 w-4 text-muted-foreground shrink-0" />
                  <span className="truncate max-w-xs">
                    {file.decryptedName ?? '[encrypted]'}
                  </span>
                </div>
              </TableCell>
              <TableCell className="text-muted-foreground">
                {file.decryptedSize ? formatBytes(file.decryptedSize) : '—'}
              </TableCell>
              <TableCell className="text-muted-foreground">
                {new Date(file.createdAt).toLocaleDateString()}
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
          )
        })}
      </TableBody>
    </Table>
  )
}
