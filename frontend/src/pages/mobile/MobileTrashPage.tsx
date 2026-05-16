import { useTranslation } from 'react-i18next'
import { MobileShell } from '@/components/mobile/MobileShell'
import { MobilePageHeader } from '@/components/mobile/MobilePageHeader'
import { EmptyState } from '@/components/ui/empty-state'
import { useTrash } from '@/hooks/useTrash'

/**
 * MobileTrashPage — `/drive/trash` mobile layout.
 *
 * PR 2 ships the visual structure with an empty-state hero. Backend support
 * for soft-delete + 30-day retention isn't wired yet — `useTrash()` returns an
 * empty array until PRs 6/7 land that work. When items do show up later, the
 * list view (strike-through name + Restore pill + ⋯ button) gets added here.
 */
export default function MobileTrashPage() {
  const { t } = useTranslation()
  const { items, emptyAll } = useTrash()

  const hasItems = items.length > 0

  return (
    <MobileShell>
      <MobilePageHeader
        title={t('nav.trash', 'Trash')}
        subtitle={t(
          'mobile.trash.subtitle',
          'Items are permanently deleted after 30 days',
        )}
        large
        right={
          hasItems ? (
            <button
              type="button"
              onClick={() => emptyAll()}
              className="bg-transparent border-0 cursor-pointer text-destructive text-sm font-medium px-3 py-2"
            >
              {t('mobile.trash.empty.action', 'Empty')}
            </button>
          ) : null
        }
      />
      <div className="flex-1 overflow-auto px-3.5 pt-3 pb-24">
        {hasItems ? (
          <div role="list" aria-label={t('nav.trash', 'Trash')}>
            {/* Item rows land in PRs 6/7 once backend support exists; see
                docs/research/ + plan file for the roadmap. */}
          </div>
        ) : (
          <EmptyState
            icon="trash"
            title={t('mobile.trash.empty.title', 'Trash is empty')}
            subtitle={t(
              'mobile.trash.empty.subtitle',
              'Deleted files appear here for 30 days',
            )}
            tint="muted"
          />
        )}
      </div>
    </MobileShell>
  )
}
