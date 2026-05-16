import { cn } from '@/lib/utils'

/**
 * SegmentedTabs — iOS-style segmented control. A track filled with
 * `surface-sunken`, each option button equal-width inside; the active
 * option lifts to `surface` with the design's `shadow-sm`. Equal-width
 * via CSS grid keyed off the option count.
 *
 * Ported verbatim from the admin design. Reusable for any in-page tab
 * group where react-router routes feel like overkill.
 */
export interface SegmentedTab<Id extends string = string> {
  id: Id
  label: string
}

interface SegmentedTabsProps<Id extends string = string> {
  tabs: ReadonlyArray<SegmentedTab<Id>>
  value: Id
  onChange: (id: Id) => void
  className?: string
}

export function SegmentedTabs<Id extends string = string>({
  tabs,
  value,
  onChange,
  className,
}: SegmentedTabsProps<Id>) {
  return (
    <div
      className={cn(
        'mx-3.5 mt-3 p-[3px] rounded-[10px] bg-surface-sunken grid gap-0.5',
        className,
      )}
      style={{ gridTemplateColumns: `repeat(${tabs.length}, minmax(0, 1fr))` }}
      role="tablist"
    >
      {tabs.map((t) => {
        const active = value === t.id
        return (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(t.id)}
            className={cn(
              'py-1.5 px-2 rounded-lg text-[13px] cursor-pointer transition-colors',
              active
                ? 'bg-surface text-text-primary font-semibold shadow-[var(--shadow-sm)]'
                : 'bg-transparent text-text-tertiary font-medium',
            )}
          >
            {t.label}
          </button>
        )
      })}
    </div>
  )
}
