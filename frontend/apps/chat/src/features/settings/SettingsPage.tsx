import { Bell, Eye, HardDrive, Keyboard, MonitorSmartphone, ShieldCheck, UserRound } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { NavLink, Navigate, useParams } from 'react-router-dom'
import { cn } from '@kutup/ui/lib/cn'
import { useChat } from '../../app/chatStore'
import { BackupSettings, StorageSettings } from './BackupSettings'
import { DevicesSettings } from './DevicesSettings'
import { NotificationSettings } from './NotificationSettings'
import { PrivacySettings } from './PrivacySettings'
import { ProfileSettings } from './ProfileSettings'

/**
 * Chat's own settings. They live here, not in the account app, because
 * they belong to this browser's chat device: its profile key, its device
 * registration, its local history and media.
 */
export function SettingsPage() {
  const { t } = useTranslation()
  const { section } = useParams()
  const { capabilities } = useChat()
  const sections = [
    { id: 'profile', label: t('chat.settings.profile'), icon: <UserRound /> },
    { id: 'notifications', label: t('chat.settings.notifications'), icon: <Bell /> },
    { id: 'privacy', label: t('chat.settings.privacy'), icon: <Eye /> },
    { id: 'devices', label: t('chat.settings.devices'), icon: <MonitorSmartphone /> },
    ...(capabilities?.backup?.alwaysEnabled ? [{ id: 'backup', label: t('chat.settings.backup'), icon: <ShieldCheck /> }] : []),
    ...(capabilities?.media ? [{ id: 'storage', label: t('chat.settings.storage'), icon: <HardDrive /> }] : []),
  ]
  if (!sections.some((s) => s.id === section)) return <Navigate to="/settings/profile" replace />

  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-6 px-4 py-6 md:flex-row md:px-8 md:py-8">
      <nav aria-label={t('chat.settings.title')} className="md:w-52 md:shrink-0">
        <h1 className="mb-3 px-3 font-display text-xl font-semibold tracking-tight">{t('chat.settings.title')}</h1>
        <ul className="flex gap-1 overflow-x-auto md:flex-col">
          {sections.map((item) => (
            <li key={item.id}>
              <NavLink
                to={`/settings/${item.id}`}
                className={({ isActive }) =>
                  cn(
                    'flex items-center gap-2.5 whitespace-nowrap rounded-md px-3 py-2 text-sm transition-colors [&_svg]:size-4',
                    'hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                    isActive ? 'bg-accent font-medium text-accent-foreground' : 'text-muted-foreground',
                  )
                }
              >
                {item.icon}
                {item.label}
              </NavLink>
            </li>
          ))}
        </ul>
        <button
          type="button"
          onClick={() => window.dispatchEvent(new Event('kutup-chat-show-shortcuts'))}
          className="mt-4 hidden w-full items-center gap-2.5 rounded-md px-3 py-2 text-left text-sm text-muted-foreground hover:bg-muted md:flex [&_svg]:size-4"
          data-testid="chat-show-shortcuts"
        >
          <Keyboard />
          {t('chat.shortcuts.title')}
        </button>
      </nav>
      <div className="min-w-0 flex-1">
        {section === 'profile' ? <ProfileSettings /> : null}
        {section === 'notifications' ? <NotificationSettings /> : null}
        {section === 'privacy' ? <PrivacySettings /> : null}
        {section === 'devices' ? <DevicesSettings /> : null}
        {section === 'backup' ? <BackupSettings /> : null}
        {section === 'storage' ? <StorageSettings /> : null}
      </div>
    </div>
  )
}

/** One settings section: its heading and a short explanation. */
export function SettingsSection({ title, description, children }: { title: string; description?: string; children: React.ReactNode }) {
  return (
    <section className="space-y-4">
      <header>
        <h2 className="text-lg font-semibold">{title}</h2>
        {description ? <p className="mt-1 text-sm text-muted-foreground">{description}</p> : null}
      </header>
      {children}
    </section>
  )
}
