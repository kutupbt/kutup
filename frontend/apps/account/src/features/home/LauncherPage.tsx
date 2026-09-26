import { HardDrive, Map, MessagesSquare } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { appUrl } from '@kutup/session/apps'
import { useRequiredSession } from '@kutup/session/store'
import { PageBody, PageHeader } from '@kutup/ui/components/page'

const APPS = [
  { id: 'drive', Icon: HardDrive },
  { id: 'chat', Icon: MessagesSquare },
  { id: 'maps', Icon: Map },
] as const

/** Where a direct sign-in lands: the apps this account can open. */
export function LauncherPage() {
  const { t } = useTranslation()
  const session = useRequiredSession()
  return (
    <PageBody>
      <PageHeader
        title={t('launcher.title', { name: session.username ?? session.email })}
        description={t('launcher.description')}
      />
      <ul className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {APPS.map(({ id, Icon }) => (
          <li key={id}>
            <a
              href={appUrl(id)}
              className="group flex items-start gap-4 rounded-lg border border-border bg-card p-5 transition-colors hover:border-primary/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <span className="flex size-11 shrink-0 items-center justify-center rounded-md bg-accent text-accent-foreground [&_svg]:size-5">
                <Icon />
              </span>
              <span className="min-w-0">
                <span className="block font-display text-lg font-semibold">{t(`apps.${id}`)}</span>
                <span className="mt-0.5 block text-sm text-muted-foreground">{t(`launcher.${id}`)}</span>
              </span>
            </a>
          </li>
        ))}
      </ul>
    </PageBody>
  )
}
