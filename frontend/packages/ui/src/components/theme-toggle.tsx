import { useTheme } from 'next-themes'
import { Monitor, Moon, Sun } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { cn } from '../lib/cn'

const OPTIONS = [
  { value: 'light', Icon: Sun, key: 'theme.light' },
  { value: 'dark', Icon: Moon, key: 'theme.dark' },
  { value: 'system', Icon: Monitor, key: 'theme.system' },
] as const

/**
 * Light / dark / system switch.
 *
 * `onChrome` says which surface it is standing on, and both answers are
 * necessary.
 *
 * **On the rail, chrome tokens throughout.** The rail has its own palette
 * (white in light, ink in dark), so the switch is drawn in the rail's colours
 * rather than the content plane's.
 *
 * **On the auth screens, content tokens**, because there is no rail there and
 * the chrome palette renders a near-white control on `bg-muted`. The first
 * screenshot of the new sign-in screen is what showed it.
 */
export function ThemeToggle({ onChrome = true }: { onChrome?: boolean } = {}) {
  const { theme, setTheme } = useTheme()
  const { t } = useTranslation()

  return (
    <div
      className={cn(
        'inline-flex rounded-md border p-0.5',
        onChrome ? 'border-chrome-border' : 'border-border',
      )}
      role="group"
    >
      {OPTIONS.map(({ value, Icon, key }) => (
        <button
          key={value}
          type="button"
          onClick={() => setTheme(value)}
          aria-label={t(key)}
          aria-pressed={theme === value}
          className={cn(
            'rounded p-1.5 transition-colors',
            theme === value
              ? onChrome
                ? 'bg-chrome-accent text-chrome-foreground'
                : 'bg-accent text-accent-foreground'
              : onChrome
                ? 'text-chrome-muted hover:bg-chrome-accent/60 hover:text-chrome-foreground'
                : 'text-muted-foreground hover:bg-accent/60 hover:text-accent-foreground',
          )}
        >
          <Icon className="h-4 w-4" />
        </button>
      ))}
    </div>
  )
}
