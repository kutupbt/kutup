import { useTranslation } from 'react-i18next'
import { Trash2 } from 'lucide-react'
import { useIsMobile } from '@/hooks/useIsMobile'
import { useTrash } from '@/hooks/useTrash'
import MobileTrashPage from '@/pages/mobile/MobileTrashPage'

/**
 * TrashPage — unified `/drive/trash` route handler.
 *
 * Forks by viewport size:
 *  - **Mobile (`<md:`)** → renders the design's full mobile page via
 *    `MobileTrashPage` (large title + Empty button + empty-state hero).
 *  - **Desktop (`md:`+)** → renders a simple desktop layout: page header
 *    with "Trash" + soft-deleted item count, plus the same empty-state hero
 *    until backend support lands (per the roadmap PR 6/7).
 *
 * The desktop layout intentionally stays minimal in PR 2; once the backend
 * has soft-delete + 30-day retention endpoints, PR 7 fleshes out the table
 * view (selection checkboxes, Restore / Delete-permanently buttons, Empty
 * Trash confirm dialog) per the `kutup-drive.html` design reference.
 */
export default function TrashPage() {
  const { t } = useTranslation()
  const isMobile = useIsMobile()
  const { items, emptyAll } = useTrash()

  if (isMobile) return <MobileTrashPage />

  const hasItems = items.length > 0

  return (
    <div className="flex-1 flex flex-col min-w-0 min-h-0">
      {/* Page header */}
      <header className="flex items-center gap-3 px-6 py-4 border-b border-border">
        <Trash2 className="h-5 w-5 text-muted-foreground" aria-hidden="true" />
        <h1 className="text-base font-semibold text-foreground">
          {t('nav.trash', 'Trash')}
        </h1>
        <span className="text-xs text-muted-foreground">
          {t('mobile.trash.subtitle', 'Items are permanently deleted after 30 days')}
        </span>
        <div className="flex-1" />
        {hasItems && (
          <button
            type="button"
            onClick={() => emptyAll()}
            className="px-3 py-1.5 text-sm font-medium text-destructive border border-destructive/30 rounded-md hover:bg-destructive/10 transition-colors cursor-pointer"
          >
            {t('mobile.trash.empty.action', 'Empty Trash')}
          </button>
        )}
      </header>

      {/* Body */}
      <div className="flex-1 overflow-auto">
        {hasItems ? (
          <div className="p-6">
            {/* Items table — PR 7 fleshes this out when backend support exists. */}
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center h-full px-6 py-16">
            <div
              className="w-16 h-16 rounded-2xl bg-muted text-muted-foreground inline-flex items-center justify-center mb-3"
              aria-hidden="true"
            >
              <Trash2 className="h-7 w-7" />
            </div>
            <div className="text-base font-semibold text-foreground">
              {t('mobile.trash.empty.title', 'Trash is empty')}
            </div>
            <div className="text-sm text-muted-foreground mt-1 max-w-md text-center">
              {t(
                'mobile.trash.empty.subtitle',
                'Deleted files appear here for 30 days',
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
