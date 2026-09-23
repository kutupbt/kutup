import { LogOut, Settings } from 'lucide-react'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from './button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from './dropdown-menu'
import { LocaleToggle } from './locale-toggle'
import { ThemeToggle } from './theme-toggle'

function initials(name: string): string {
  const parts = name.trim().split(/[\s@._-]+/).filter(Boolean)
  const letters = parts.slice(0, 2).map((p) => p[0]!.toLocaleUpperCase())
  return letters.join('') || '?'
}

/**
 * The account menu in the header's top-right corner (Proton's UserDropdown):
 * who is signed in, a link to account settings (on the account app), the
 * theme and language controls, and sign out.
 */
export function UserMenu({
  name,
  email,
  settingsHref,
  onSignOut,
  children,
}: {
  /** Username, or the email when there is none. */
  name: string
  email: string
  /** Absolute URL of the account app's settings for this product. */
  settingsHref: string
  onSignOut: () => void
  /** Extra items above the separator (Drive: keyboard shortcuts). */
  children?: ReactNode
}) {
  const { t } = useTranslation()
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" className="rounded-full" aria-label={t('shell.accountMenu')}>
          <span className="flex size-8 items-center justify-center rounded-full bg-primary text-xs font-semibold text-primary-foreground">
            {initials(name)}
          </span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-72">
        <DropdownMenuLabel>
          <span className="block truncate text-sm font-medium text-foreground">{name}</span>
          {email !== name ? (
            <span className="block truncate text-xs font-normal text-muted-foreground">{email}</span>
          ) : null}
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild>
          <a href={settingsHref}>
            <Settings />
            {t('shell.accountSettings')}
          </a>
        </DropdownMenuItem>
        {children}
        <DropdownMenuSeparator />
        <div className="flex items-center justify-between gap-2 px-2 py-1.5">
          <span className="text-sm text-muted-foreground">{t('shell.appearance')}</span>
          <ThemeToggle onChrome={false} />
        </div>
        <div className="flex items-center justify-between gap-2 px-2 py-1.5">
          <span className="text-sm text-muted-foreground">{t('shell.language')}</span>
          <LocaleToggle onChrome={false} />
        </div>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={onSignOut}>
          <LogOut />
          {t('shell.signOut')}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
