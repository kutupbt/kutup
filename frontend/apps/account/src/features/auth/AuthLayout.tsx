import type { ReactNode } from 'react'
import { KutupLogo } from '@kutup/ui/components/brand'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@kutup/ui/components/card'
import { LocaleToggle } from '@kutup/ui/components/locale-toggle'
import { ThemeToggle } from '@kutup/ui/components/theme-toggle'

/**
 * The ground every screen outside the shell stands on (sign-in, registration,
 * recovery, the fork hand-off): shadcn's login-03 — the mark above a centred
 * card on a muted ground, so the card separates without a heavy border.
 * Language and theme sit in the corner: somebody may need Turkish or a dark
 * screen before they can sign in.
 */
export function AuthLayout({
  title,
  description,
  width = 'sm',
  children,
}: {
  title: string
  description?: string
  /** `md` for the recovery phrase, whose 24 words need two columns. */
  width?: 'sm' | 'md'
  children: ReactNode
}) {
  return (
    <div className="relative flex min-h-svh flex-col items-center justify-center gap-6 bg-muted p-6 text-foreground md:p-10">
      <div className="absolute right-4 top-4 flex items-center gap-2">
        <LocaleToggle onChrome={false} />
        <ThemeToggle onChrome={false} />
      </div>
      <main className={width === 'md' ? 'flex w-full max-w-lg flex-col gap-6' : 'flex w-full max-w-sm flex-col gap-6'}>
        <div className="flex items-center justify-center gap-3">
          <KutupLogo size={40} />
          <span className="font-display text-[28px] font-semibold tracking-[0.12em]">Kutup</span>
        </div>
        <Card>
          <CardHeader className="text-center">
            <CardTitle as="h1" className="text-xl">
              {title}
            </CardTitle>
            {description ? <CardDescription>{description}</CardDescription> : null}
          </CardHeader>
          <CardContent>{children}</CardContent>
        </Card>
      </main>
    </div>
  )
}
