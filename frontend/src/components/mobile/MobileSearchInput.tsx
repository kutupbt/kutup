import { useTranslation } from 'react-i18next'
import { Icon, ICONS } from '@/components/mobile/Icon'

/**
 * MobileSearchInput — the slide-in search row that replaces the page header
 * content when the user taps the search icon on the Files tab.
 *
 * Layout: a rounded input on the left + a "Cancel" button on the right.
 * The input has its own clear-x button when there's a value.
 */
interface MobileSearchInputProps {
  value: string
  onChange: (next: string) => void
  onCancel: () => void
  autoFocus?: boolean
}

export function MobileSearchInput({
  value,
  onChange,
  onCancel,
  autoFocus,
}: MobileSearchInputProps) {
  const { t } = useTranslation()

  return (
    <div className="px-3.5 pb-3 pt-2 flex items-center gap-2">
      <div className="flex-1 h-9.5 rounded-[10px] bg-surface-sunken flex items-center px-3 gap-2 border border-border-light">
        <Icon d={ICONS.search} size={16} color="var(--text-tertiary)" />
        <input
          autoFocus={autoFocus}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={t('mobile.files.search.placeholder', 'Search in Kutup…')}
          aria-label={t('mobile.files.search.placeholder', 'Search in Kutup…')}
          className="flex-1 h-full border-0 outline-none bg-transparent text-sm text-text-primary placeholder:text-text-tertiary"
        />
        {value && (
          <button
            type="button"
            onClick={() => onChange('')}
            aria-label={t('mobile.files.search.clear', 'Clear search')}
            className="bg-border border-0 cursor-pointer w-4.5 h-4.5 rounded-full flex items-center justify-center text-surface"
          >
            <Icon d={ICONS.x} size={11} />
          </button>
        )}
      </div>
      <button
        type="button"
        onClick={onCancel}
        className="bg-transparent border-0 cursor-pointer text-primary text-sm font-medium px-1"
      >
        {t('mobile.cancel', 'Cancel')}
      </button>
    </div>
  )
}
