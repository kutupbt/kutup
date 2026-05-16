import type { ReactNode } from 'react'

/**
 * AdminTopBar — sticky header above each tab's content area on the desktop
 * admin page. Pairs a left-side title block (title + optional subtitle)
 * with a right-side action slot (free-form JSX so each tab can drop in its
 * own buttons — e.g. "Refresh" + "Create user" on the Users tab).
 *
 * Sticky positioning keeps the title visible while the table scrolls under
 * it. The surface + border-light styling matches the rest of the admin
 * chrome.
 */
interface AdminTopBarProps {
  title: string
  subtitle?: string
  /** Right-side action slot. Buttons / IconButtons / etc. */
  action?: ReactNode
}

export function AdminTopBar({ title, subtitle, action }: AdminTopBarProps) {
  return (
    <div className="sticky top-0 z-10 flex items-center justify-between px-8 py-4 bg-surface border-b border-border-light">
      <div className="min-w-0">
        <div className="text-[22px] font-bold text-text-primary tracking-[-0.3px] truncate">
          {title}
        </div>
        {subtitle && (
          <div className="text-[13px] text-text-tertiary mt-0.5 truncate">
            {subtitle}
          </div>
        )}
      </div>
      {action && (
        <div className="flex items-center gap-2.5 shrink-0">{action}</div>
      )}
    </div>
  )
}
