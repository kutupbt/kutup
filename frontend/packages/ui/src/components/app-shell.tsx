import * as DialogPrimitive from '@radix-ui/react-dialog'
import { Menu, X } from 'lucide-react'
import { useEffect, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { NavLink, useLocation } from 'react-router-dom'
import { cn } from '../lib/cn'
import { BrandLockup } from './brand'
import { Button } from './button'
import { Spine } from './spine'

/**
 * The frame every Kutup app shares (Proton's PrivateAppContainer, asec's
 * chrome): a dark sidebar that stays dark in both themes, and a content
 * column with a thin header.
 *
 * Sidebar, top to bottom: the app switcher beside the brand lockup, the
 * app's primary action ("New"), its navigation, and a footer slot (the
 * storage meter in Drive). The header carries an optional leading slot
 * (search, a title) and the user menu.
 *
 * Below `md` the sidebar becomes a slide-in sheet opened from the header;
 * it closes itself on navigation.
 */
export interface AppShellProps {
  /** The app's short name next to the logo: "Drive", "Chat", "Account". */
  appName: string
  switcher?: ReactNode
  primaryAction?: ReactNode
  nav: ReactNode
  sidebarFooter?: ReactNode
  headerStart?: ReactNode
  headerEnd?: ReactNode
  children: ReactNode
}

function SidebarContent({
  appName,
  switcher,
  primaryAction,
  nav,
  sidebarFooter,
}: Pick<AppShellProps, 'appName' | 'switcher' | 'primaryAction' | 'nav' | 'sidebarFooter'>) {
  const { t } = useTranslation()
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-14 shrink-0 items-center gap-1 px-3">
        {switcher}
        <BrandLockup app={appName} className="px-1" />
      </div>
      {primaryAction ? <div className="px-3 pb-3 pt-1">{primaryAction}</div> : null}
      <nav aria-label={t('shell.navigation')} className="min-h-0 flex-1 overflow-y-auto px-2 py-1">
        <ul className="space-y-0.5">{nav}</ul>
      </nav>
      {sidebarFooter ? (
        <div className="shrink-0 border-t border-chrome-border px-3 py-3">{sidebarFooter}</div>
      ) : null}
    </div>
  )
}

export function AppShell(props: AppShellProps) {
  const { t } = useTranslation()
  const [sheetOpen, setSheetOpen] = useState(false)
  const location = useLocation()

  useEffect(() => {
    setSheetOpen(false)
  }, [location.pathname])

  return (
    <div className="flex min-h-svh bg-background">
      <aside className="sticky top-0 hidden h-svh w-64 shrink-0 bg-chrome text-chrome-foreground md:block">
        <SidebarContent {...props} />
      </aside>

      <DialogPrimitive.Root open={sheetOpen} onOpenChange={setSheetOpen}>
        <DialogPrimitive.Portal>
          <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-foreground/40 md:hidden" />
          <DialogPrimitive.Content
            className="fixed inset-y-0 left-0 z-50 w-72 max-w-[85vw] bg-chrome text-chrome-foreground shadow-lg focus:outline-none md:hidden"
          >
            <DialogPrimitive.Title className="sr-only">{t('shell.navigation')}</DialogPrimitive.Title>
            <DialogPrimitive.Description className="sr-only">
              {t('shell.navigationDescription')}
            </DialogPrimitive.Description>
            <SidebarContent {...props} />
            <DialogPrimitive.Close asChild>
              <Button
                variant="chrome"
                size="icon"
                className="absolute right-2 top-2.5"
                aria-label={t('common.close')}
              >
                <X />
              </Button>
            </DialogPrimitive.Close>
          </DialogPrimitive.Content>
        </DialogPrimitive.Portal>
      </DialogPrimitive.Root>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-14 shrink-0 items-center gap-2 border-b border-border bg-background/95 px-3 backdrop-blur-sm md:px-6">
          <Button
            variant="ghost"
            size="icon"
            className="md:hidden"
            aria-label={t('shell.openNavigation')}
            onClick={() => setSheetOpen(true)}
          >
            <Menu />
          </Button>
          <div className="min-w-0 flex-1">{props.headerStart}</div>
          <div className="flex shrink-0 items-center gap-1">{props.headerEnd}</div>
        </header>
        <main className="min-w-0 flex-1">{props.children}</main>
      </div>
    </div>
  )
}

/**
 * One sidebar entry. The active entry gets the chrome accent and the ice
 * spine; `end` matches exactly (for an index route like "/").
 */
export function SidebarNavLink({
  to,
  icon,
  label,
  end,
  trailing,
}: {
  to: string
  icon: ReactNode
  label: string
  end?: boolean
  trailing?: ReactNode
}) {
  return (
    <li>
      <NavLink
        to={to}
        end={end}
        className={({ isActive }) =>
          cn(
            'relative flex h-9 items-center gap-3 rounded-md px-3 text-sm transition-colors',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-chrome-active',
            '[&_svg]:size-4 [&_svg]:shrink-0',
            isActive
              ? 'bg-chrome-accent font-medium text-chrome-foreground'
              : 'text-chrome-muted hover:bg-chrome-accent/60 hover:text-chrome-foreground',
          )
        }
      >
        {({ isActive }) => (
          <>
            {isActive ? <Spine tone="chrome" /> : null}
            {icon}
            <span className="min-w-0 flex-1 truncate">{label}</span>
            {trailing}
          </>
        )}
      </NavLink>
    </li>
  )
}
