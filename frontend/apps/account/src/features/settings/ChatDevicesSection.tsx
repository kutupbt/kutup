import { useQuery } from '@tanstack/react-query'
import { ExternalLink, MessagesSquare } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import api from '@kutup/session/client'
import { appUrl } from '@kutup/session/apps'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Card } from '@kutup/ui/components/card'
import { Mono } from '@kutup/ui/components/mono'
import { Section } from '@kutup/ui/components/page'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { formatInstant } from '@kutup/ui/lib/format'

interface ChatDevice {
  deviceId: number
  name: string
  createdAt: string
  lastSeenAt?: string | null
}

/**
 * The browsers with Chat set up. They are listed here with everything else
 * this account signs in with; removing one happens in Chat, because it
 * re-signs the account's device list and takes the device out of every
 * group, which only Chat can do.
 */
export function ChatDevicesSection() {
  const { t, i18n } = useTranslation()
  const devices = useQuery({
    queryKey: ['chat-devices'],
    queryFn: async () => (await api.get<{ devices: ChatDevice[] }>('/chat/device')).data.devices,
  })
  const manage = appUrl('chat', '/settings/devices')

  return (
    <Section
      title={t('settings.chatDevices.title')}
      description={t('settings.chatDevices.description')}
      actions={
        <Button asChild variant="outline">
          <a href={manage} data-testid="account-chat-devices-manage">
            <ExternalLink />
            {t('settings.chatDevices.manage')}
          </a>
        </Button>
      }
    >
      {devices.isError ? <Alert variant="error">{apiErrorMessage(devices.error, t('common.tryAgain'))}</Alert> : null}
      {devices.isPending ? <LoadingPanel label={t('common.loading')} /> : null}
      {devices.data && devices.data.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t('settings.chatDevices.none')}</p>
      ) : null}
      {devices.data && devices.data.length > 0 ? (
        <Card className="divide-y divide-border p-0" data-testid="account-chat-devices">
          {devices.data.map((device) => (
            <div key={device.deviceId} className="flex flex-wrap items-center gap-4 p-4">
              <span className="flex size-10 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground [&_svg]:size-5">
                <MessagesSquare />
              </span>
              <div className="min-w-0 flex-1 space-y-1">
                <p className="flex flex-wrap items-center gap-2 font-medium">
                  {device.name || t('settings.chatDevices.unnamed')}
                  <Mono className="text-xs text-muted-foreground">#{device.deviceId}</Mono>
                </p>
                <p className="text-xs text-muted-foreground">
                  {t('settings.devices.added', { when: formatInstant(device.createdAt, i18n.language) })}
                  {device.lastSeenAt
                    ? ` · ${t('settings.devices.lastSeen', { when: formatInstant(device.lastSeenAt, i18n.language) })}`
                    : ''}
                </p>
              </div>
            </div>
          ))}
        </Card>
      ) : null}
    </Section>
  )
}
