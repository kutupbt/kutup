import * as DropdownMenuPrimitive from '@radix-ui/react-dropdown-menu'
import { Grip } from 'lucide-react'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { cn } from '../lib/cn'
import { Button } from './button'
import { DropdownMenu, DropdownMenuContent, DropdownMenuTrigger } from './dropdown-menu'

export interface SwitcherApp {
  id: string
  name: string
  /** Absolute URL on the app's own origin. */
  href: string
  icon: ReactNode
}

/**
 * The apps menu, top right beside the account menu (Google's "waffle",
 * Proton's AppsDropdown). With three apps it is a row of large tiles rather
 * than a sparse grid; it grows into a grid as apps are added.
 *
 * The current app is marked (`aria-current`) and stays in this tab; the
 * others open in a new tab, the way Proton and Google do, so the work in
 * this one is not lost. Nothing renders when there is only one app.
 */
export function AppSwitcher({ apps, currentId }: { apps: SwitcherApp[]; currentId: string }) {
  const { t } = useTranslation()
  if (apps.length <= 1) return null

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" aria-label={t('shell.switchApp')} title={t('shell.apps')}>
          <Grip />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" sideOffset={8} className="w-80 rounded-xl p-3">
        <p className="px-1 pb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">{t('shell.apps')}</p>
        <div className="grid grid-cols-3 gap-2">
          {apps.map((app) => {
            const current = app.id === currentId
            return (
              <DropdownMenuPrimitive.Item key={app.id} asChild>
                <a
                  href={app.href}
                  target={current ? '_self' : '_blank'}
                  rel="noopener"
                  aria-current={current ? 'page' : undefined}
                  className={cn(
                    'flex flex-col items-center gap-2 rounded-lg px-2 pb-2.5 pt-3 text-sm outline-none transition-colors',
                    'hover:bg-accent focus:bg-accent focus-visible:ring-2 focus-visible:ring-ring',
                    current && 'bg-accent font-medium',
                  )}
                >
                  <span
                    className={cn(
                      'flex size-12 items-center justify-center rounded-xl [&_svg]:size-6',
                      current ? 'bg-primary text-primary-foreground' : 'bg-muted text-primary',
                    )}
                  >
                    {app.icon}
                  </span>
                  <span>{app.name}</span>
                </a>
              </DropdownMenuPrimitive.Item>
            )
          })}
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
