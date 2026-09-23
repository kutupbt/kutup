import { LayoutGrid } from 'lucide-react'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { cn } from '../lib/cn'
import { Button } from './button'
import { DropdownMenu, DropdownMenuContent, DropdownMenuTrigger } from './dropdown-menu'
import * as DropdownMenuPrimitive from '@radix-ui/react-dropdown-menu'
import { Spine } from './spine'

export interface SwitcherApp {
  id: string
  name: string
  /** Absolute URL on the app's own origin. */
  href: string
  icon: ReactNode
}

/**
 * Proton's AppsDropdown: a grid button beside the logo listing the Kutup
 * apps. The current app is marked (`aria-current`, spine) and stays in this
 * tab; the others open in a new tab, the way Proton and Google do, so the
 * work in this one is not lost. Nothing renders when there is only one app.
 */
export function AppSwitcher({ apps, currentId }: { apps: SwitcherApp[]; currentId: string }) {
  const { t } = useTranslation()
  if (apps.length <= 1) return null

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="chrome" size="icon" aria-label={t('shell.switchApp')}>
          <LayoutGrid />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-64 p-2">
        <p className="px-2 pb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
          {t('shell.apps')}
        </p>
        <div className="grid grid-cols-2 gap-1">
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
                    'relative flex flex-col items-center gap-2 rounded-md px-2 py-3 text-sm outline-none transition-colors',
                    'hover:bg-accent hover:text-accent-foreground focus:bg-accent focus:text-accent-foreground',
                    '[&_svg]:size-6',
                    current && 'bg-accent font-medium text-accent-foreground',
                  )}
                >
                  {current ? <Spine tone="brand" /> : null}
                  {app.icon}
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
