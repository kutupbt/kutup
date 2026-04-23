import { ChevronRight } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import type { Collection } from '@/types/drive'

interface Props {
  viewMode: 'myfiles' | 'shared'
  currentFolder: Collection | null
  myFilesCollection: Collection | null
  navigationStack: Collection[]
  onNavigateTo: (index: number) => void
  onGoHome: () => void
  onGoShared: () => void
}

export default function DriveBreadcrumb({
  viewMode,
  currentFolder,
  myFilesCollection,
  navigationStack,
  onNavigateTo,
  onGoHome,
  onGoShared,
}: Props) {
  const { t } = useTranslation()
  const rootLabel = viewMode === 'shared' ? t('nav.sharedWithMe') : t('nav.myFiles')
  const isAtRoot =
    !currentFolder ||
    (viewMode === 'myfiles' && currentFolder.id === myFilesCollection?.id)

  return (
    <nav className="flex items-center gap-1 text-sm text-muted-foreground mb-4 flex-wrap">
      <Button
        variant="ghost"
        size="sm"
        className="h-7 px-2 text-muted-foreground hover:text-foreground"
        onClick={viewMode === 'shared' ? onGoShared : onGoHome}
      >
        {rootLabel}
      </Button>

      {navigationStack.map((col, i) => (
        <span key={col.id} className="flex items-center gap-1">
          <ChevronRight className="h-3.5 w-3.5" />
          <Button
            variant="ghost"
            size="sm"
            className="h-7 px-2 text-muted-foreground hover:text-foreground"
            onClick={() => onNavigateTo(i)}
          >
            {col.decryptedName}
          </Button>
        </span>
      ))}

      {!isAtRoot && currentFolder && (
        <span className="flex items-center gap-1">
          <ChevronRight className="h-3.5 w-3.5" />
          <span className="px-2 text-foreground font-medium">{currentFolder.decryptedName}</span>
        </span>
      )}
    </nav>
  )
}
