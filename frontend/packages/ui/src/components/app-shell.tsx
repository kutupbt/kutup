import * as DialogPrimitive from '@radix-ui/react-dialog'
import { Menu, RotateCw, X } from 'lucide-react'
import { useEffect, useState, type DragEvent, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { NavLink, useLocation } from 'react-router-dom'
import { cn } from '../lib/cn'
import { BrandLockup } from './brand'
import { Button } from './button'
import { Spine } from './spine'
import { useSidebarRefresh, type SidebarRefresh } from '../lib/sidebarRefresh'

/**
 * The frame every Kutup app shares (Proton's PrivateAppContainer, asec's
 * chrome): a sidebar on its own chrome palette (white in light, ink in
 * dark), and a content column with a thin header.
 *
 * Sidebar, top to bottom: the brand lockup, the app's primary action
 * ("New"), its navigation, and a footer slot (the storage meter in Drive).
 * It holds only what is always there, so it can be used without looking.
 * The header carries the app's search (or a title) on the left and the
 * account-wide controls on the right: the app switcher, then the user menu,
 * where Google and Microsoft put them.
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
  /** Content edge to edge (Drive's file list); pages are padded otherwise. */
  flush?: boolean
  /** Shown above the content, under the header: the account's state (HeadStateBanner). */
  banner?: ReactNode
  children: ReactNode
}

function SidebarContent({
  appName,
  primaryAction,
  nav,
  sidebarFooter,
}: Pick<AppShellProps, 'appName' | 'primaryAction' | 'nav' | 'sidebarFooter'>) {
  const { t } = useTranslation()
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-14 shrink-0 items-center px-4">
        <BrandLockup app={appName} />
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
      <aside className="sticky top-0 hidden h-svh w-64 shrink-0 border-r border-chrome-border bg-chrome text-chrome-foreground md:block">
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
          <div className="flex shrink-0 items-center gap-1">
            {props.switcher}
            {props.headerEnd}
          </div>
        </header>
        {props.banner}
        <main className={cn('min-w-0 flex-1', !props.flush && 'px-4 py-6 md:px-8 md:py-8')}>
          {props.children}
        </main>
      </div>
    </div>
  )
}

/**
 * One sidebar entry. The active entry gets the chrome accent and the ice
 * spine; `end` matches exactly (for an index route like "/").
 */
/** Something that may be dropped on a sidebar link (mail on a folder). */
export interface SidebarDrop {
  /** Whether a drag carrying these types can land here. */
  accepts: (types: readonly string[]) => boolean
  onDrop: (data: DataTransfer) => void
}

export function SidebarNavLink({
  to,
  icon,
  label,
  end,
  trailing,
  drop,
  refresh,
}: {
  to: string
  icon: ReactNode
  label: string
  end?: boolean
  trailing?: ReactNode
  drop?: SidebarDrop
  /** Fetches the open place again: a button on the open row, and a click on it while open (Proton's sidebar). */
  refresh?: SidebarRefresh
}) {
  const [over, setOver] = useState(false)
  const refreshing = useSidebarRefresh(to, refresh)
  const dropProps = drop
    ? {
        onDragOver: (e: DragEvent<HTMLLIElement>) => {
          if (!drop.accepts(e.dataTransfer.types)) return
          e.preventDefault()
          e.dataTransfer.dropEffect = 'move'
          setOver(true)
        },
        onDragLeave: () => setOver(false),
        onDrop: (e: DragEvent<HTMLLIElement>) => {
          setOver(false)
          if (!drop.accepts(e.dataTransfer.types)) return
          e.preventDefault()
          drop.onDrop(e.dataTransfer)
        },
      }
    : {}
  return (
    <li {...dropProps} className="group/nav relative">
      <NavLink
        to={to}
        end={end}
        onClick={refreshing.onClick}
        className={({ isActive }) =>
          cn(
            'relative flex h-9 items-center gap-3 rounded-md px-3 text-sm transition-colors',
            isActive && refresh && 'pr-9',
            over && 'ring-2 ring-chrome-active',
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
      {refresh ? <SidebarRefreshButton to={to} end={end} refresh={refresh} state={refreshing} /> : null}
    </li>
  )
}

/** The open row's refresh button: shown on hover or focus, and while it spins. */
export function SidebarRefreshButton({
  to,
  end,
  refresh,
  state,
  className,
}: {
  to: string
  end?: boolean
  refresh: SidebarRefresh
  state: ReturnType<typeof useSidebarRefresh>
  /** Where it sits on the row; the right edge by default. */
  className?: string
}) {
  const location = useLocation()
  const open = end ? location.pathname === to : location.pathname === to || location.pathname.startsWith(`${to}/`)
  if (!open) return null
  return (
    <button
      type="button"
      aria-label={refresh.label}
      title={refresh.label}
      aria-busy={state.busy}
      onClick={state.start}
      className={cn(
        'absolute top-1/2 -translate-y-1/2 rounded p-1 text-chrome-muted hover:bg-chrome-accent hover:text-chrome-foreground',
        className ?? 'right-1.5',
        'focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-chrome-active',
        state.busy ? 'opacity-100' : 'opacity-0 group-hover/nav:opacity-100 group-hover/place:opacity-100',
      )}
    >
      <RotateCw className={cn('size-3.5', state.busy && 'animate-spin')} aria-hidden />
    </button>
  )
}
