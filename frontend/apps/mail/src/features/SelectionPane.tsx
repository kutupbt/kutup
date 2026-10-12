import { Mail } from 'lucide-react'
import { Trans, useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'

interface Props {
  /** The place's name. */
  name: string
  /** A label (rows tagged with it) rather than a folder. */
  label: boolean
  conversations: boolean
  /** Rows checked in the list. */
  checked: number
  /** Rows in the place with the list's filters; unknown while loading. */
  total: number | null
  /** The list's search. */
  q: string
  onClear: () => void
}

/**
 * Proton's SelectionPane, beside the list when nothing is open or rows are
 * checked: the place and how many it holds, or how many are chosen, with
 * Clear selection.
 */
export function SelectionPane({ name, label, conversations, checked, total, q, onClear }: Props) {
  const { t } = useTranslation()
  const unit = conversations ? 'conversations' : 'messages'
  const count = checked || total || 0
  const key = q && !checked ? 'results' : `${checked ? 'selected' : 'stored'}.${label ? 'label' : 'folder'}.${unit}`
  const bold = { strong: <strong className="font-semibold text-foreground" /> }
  return (
    <section aria-label={t('selectionPane.label')} className="flex h-full flex-col items-center justify-center gap-3 p-6 text-center text-muted-foreground">
      <Mail className="size-10" aria-hidden />
      {checked === 0 && name ? <p className="max-w-full truncate text-lg font-semibold">{name}</p> : null}
      {checked || (total ?? 0) > 0 ? (
        <p className="text-sm">
          <Trans i18nKey={`selectionPane.${key}`} count={count} values={{ count, name }} components={bold} />
        </p>
      ) : null}
      {checked > 0 ? (
        <Button variant="outline" onClick={onClear}>
          {t('selectionPane.clear')}
        </Button>
      ) : (
        <p className="text-xs">{t('shortcuts.hint')}</p>
      )}
    </section>
  )
}
