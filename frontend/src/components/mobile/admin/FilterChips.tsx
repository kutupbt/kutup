import { cn } from '@/lib/utils'

/**
 * FilterChips — horizontal-scrolling row of pill-shaped filters with
 * optional count badges. Active chip filled with primary, inactive uses
 * the design's surface/border treatment.
 *
 * Ported from the design (`kutup-admin-mobile.html`). Used by the Users
 * tab; could be reused for Files/Shared filtering in later PRs.
 */
export interface FilterOption<Id extends string = string> {
  id: Id
  label: string
  count?: number | null
}

interface FilterChipsProps<Id extends string = string> {
  value: Id
  onChange: (id: Id) => void
  options: ReadonlyArray<FilterOption<Id>>
  className?: string
}

export function FilterChips<Id extends string = string>({
  value,
  onChange,
  options,
  className,
}: FilterChipsProps<Id>) {
  return (
    <div
      className={cn(
        '-mx-3.5 px-3.5 pb-1 flex gap-1.5 overflow-x-auto',
        className,
      )}
      role="tablist"
    >
      {options.map((o) => {
        const active = value === o.id
        return (
          <button
            key={o.id}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(o.id)}
            className={cn(
              'shrink-0 px-3 py-1.5 rounded-[14px] border cursor-pointer transition-colors',
              'text-[12px] font-medium inline-flex items-center gap-1.5',
              active
                ? 'bg-primary text-white border-primary'
                : 'bg-surface text-text-secondary border-border hover:bg-surface-raised',
            )}
          >
            <span>{o.label}</span>
            {o.count != null && (
              <span
                className={cn(
                  'text-[10px] font-bold px-[5px] leading-[14px] rounded-[7px]',
                  active
                    ? 'bg-white/25 text-white'
                    : 'bg-surface-sunken text-text-tertiary',
                )}
              >
                {o.count}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}
