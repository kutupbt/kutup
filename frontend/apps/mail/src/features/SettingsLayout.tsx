import { useTranslation } from 'react-i18next'
import { NavLink, Outlet } from 'react-router-dom'
import { cn } from '@kutup/ui/lib/cn'

const TABS = [
  { to: '/settings/folders', key: 'settings.folders' },
  { to: '/settings/filters', key: 'settings.filters' },
] as const

/** Mail → Settings (Proton's mail settings): one page per section, as tabs. */
export function SettingsLayout() {
  const { t } = useTranslation()
  return (
    // Mail's shell is flush (the list runs edge to edge); settings have their own margins.
    <div className="h-full overflow-y-auto px-4 py-6 md:px-8">
      <nav aria-label={t('settings.title')} className="mb-6 flex gap-1 border-b border-border">
        {TABS.map((tab) => (
          <NavLink
            key={tab.to}
            to={tab.to}
            className={({ isActive }) =>
              cn(
                '-mb-px border-b-2 px-3 py-2 text-sm transition-colors',
                isActive ? 'border-primary font-medium text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground',
              )
            }
          >
            {t(tab.key)}
          </NavLink>
        ))}
      </nav>
      <Outlet />
    </div>
  )
}
