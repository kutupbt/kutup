import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { webAssemblySupported } from '../lib/webAssembly'
import { KutupLogo } from './brand'
import { Button } from './button'

/**
 * Renders the app only where WebAssembly runs; elsewhere a page that says
 * why nothing works, instead of every action failing with a generic error.
 * Safari's Lockdown Mode is the common case, and it can be lifted for one
 * site, so the page says how.
 */
export function WebAssemblyGate({ children }: { children: ReactNode }) {
  if (webAssemblySupported()) return <>{children}</>
  return <WebAssemblyRequired />
}

export function WebAssemblyRequired() {
  const { t } = useTranslation()
  return (
    <main className="mx-auto flex min-h-dvh w-full max-w-lg flex-col justify-center gap-5 px-4 py-10">
      <KutupLogo size={40} />
      <h1 className="font-display text-2xl font-semibold tracking-tight">{t('webAssembly.title')}</h1>
      <p className="text-sm text-muted-foreground">{t('webAssembly.why')}</p>
      <section className="space-y-2 rounded-lg border p-4">
        <h2 className="text-sm font-semibold">{t('webAssembly.lockdownTitle')}</h2>
        <p className="text-sm text-muted-foreground">{t('webAssembly.lockdownBody')}</p>
        <ol className="list-decimal space-y-1 pl-5 text-sm">
          <li>{t('webAssembly.lockdownStep1')}</li>
          <li>{t('webAssembly.lockdownStep2')}</li>
          <li>{t('webAssembly.lockdownStep3')}</li>
        </ol>
        <p className="text-sm text-muted-foreground">{t('webAssembly.lockdownSettings')}</p>
      </section>
      <p className="text-sm text-muted-foreground">{t('webAssembly.otherBrowsers')}</p>
      <div>
        <Button onClick={() => window.location.reload()}>{t('webAssembly.reload')}</Button>
      </div>
    </main>
  )
}
