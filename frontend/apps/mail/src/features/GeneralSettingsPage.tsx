import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { PAGE_SIZES, useImageSenders, useMailSettings, useRemoveImageSender, useUpdateMailSettings, type MailSettings } from '@kutup/mail-core/api'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { useContentSearch, useContentSearchState } from '@kutup/mail-core/contentSearch'
import { notificationStatus, requestNotifications, showNotification, type NotificationStatus } from '@kutup/ui/lib/desktopNotifications'
import { registerMailtoHandler } from './mailto'

function Setting({ label, hint, checked, onChange }: { label: string; hint: string; checked: boolean; onChange: (on: boolean) => void }) {
  return (
    <label className="flex items-start gap-3 rounded-lg border border-border p-4">
      <Checkbox className="mt-0.5" checked={checked} onCheckedChange={(on) => onChange(on === true)} />
      <span>
        <span className="block text-sm font-medium">{label}</span>
        <span className="block text-sm text-muted-foreground">{hint}</span>
      </span>
    </label>
  )
}

/** Settings → General (Proton's Messages section, and its External PGP settings): conversation grouping, page size, auto-delete, All mail; signing, the attached key and the PGP scheme for outside mail. */
/** Proton's DesktopNotificationPanel: the browser's permission, asked for here, and a test. */
function NotificationSettings() {
  const { t } = useTranslation()
  const [status, setStatus] = useState<NotificationStatus>(notificationStatus)
  return (
    <section className="mt-8 space-y-3" aria-labelledby="notifications-heading">
      <h2 id="notifications-heading" className="text-sm font-medium">
        {t('notifications.settingsTitle')}
      </h2>
      <div className="flex flex-col gap-3 rounded-lg border border-border p-4 sm:flex-row sm:items-center sm:justify-between">
        <span>
          <span className="block text-sm font-medium">{t(`notifications.status.${status}`)}</span>
          <span className="block text-sm text-muted-foreground">{t('notifications.settingsHint')}</span>
        </span>
        {status === 'granted' ? (
          <Button variant="outline" onClick={() => showNotification(t('notifications.testTitle'), { body: t('notifications.testBody'), tag: 'kutup-mail-test' })}>
            {t('notifications.test')}
          </Button>
        ) : status === 'default' ? (
          <Button onClick={() => void requestNotifications().then(setStatus)}>{t('notifications.enable')}</Button>
        ) : null}
      </div>
    </section>
  )
}

/** Proton's Clear browser data, for body search's index. */
function ContentSearchSettings() {
  const { t } = useTranslation()
  const search = useContentSearch()
  const state = useContentSearchState(search)
  if (!search) return null
  const kept = state.status !== 'off' || state.indexed > 0
  return (
    <section className="mt-8 space-y-3" aria-labelledby="content-search-heading">
      <h2 id="content-search-heading" className="text-sm font-medium">
        {t('contentSearch.settingsTitle')}
      </h2>
      <div className="flex flex-col gap-3 rounded-lg border border-border p-4 sm:flex-row sm:items-center sm:justify-between">
        <span className="text-sm text-muted-foreground">{kept ? t('contentSearch.settingsOn', { count: state.indexed }) : t('contentSearch.settingsOff')}</span>
        {kept ? (
          <Button variant="outline" onClick={() => void search.deleteAll().then(() => toast.success(t('contentSearch.deleted')))}>
            {t('contentSearch.delete')}
          </Button>
        ) : null}
      </div>
    </section>
  )
}

export function GeneralSettingsPage() {
  const { t } = useTranslation()
  const settings = useMailSettings()
  const update = useUpdateMailSettings()
  const imageSenders = useImageSenders()
  const removeImageSender = useRemoveImageSender()
  if (settings.isPending) return <LoadingPanel label={t('common.loading')} />
  if (settings.isError) return <Alert variant="error">{apiErrorMessage(settings.error, t('common.tryAgain'))}</Alert>
  const save = (change: Partial<MailSettings>) =>
    update.mutate(change, {
      onSuccess: () => toast.success(t('general.saved')),
      onError: (error) => toast.error(apiErrorMessage(error, t('common.tryAgain'))),
    })
  return (
    <PageBody>
      <PageHeader title={t('general.title')} />
      <div className="space-y-3">
        <Setting
          label={t('general.conversations')}
          hint={t('general.conversationsHint')}
          checked={settings.data.viewMode === 'conversation'}
          onChange={(on) => save({ viewMode: on ? 'conversation' : 'message' })}
        />
        <div className="flex flex-col gap-3 rounded-lg border border-border p-4 sm:flex-row sm:items-center sm:justify-between">
          <label htmlFor="page-size" className="block text-sm font-medium">
            {settings.data.viewMode === 'conversation' ? t('general.pageSizeConversations') : t('general.pageSizeMessages')}
          </label>
          <Select value={String(settings.data.pageSize)} onValueChange={(size) => save({ pageSize: Number(size) })}>
            <SelectTrigger id="page-size" className="sm:w-48">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PAGE_SIZES.map((size) => (
                <SelectItem key={size} value={String(size)}>
                  {size}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="flex flex-col gap-3 rounded-lg border border-border p-4 sm:flex-row sm:items-center sm:justify-between">
          <span>
            <label htmlFor="spam-action" className="block text-sm font-medium">
              {t('general.spamAction')}
            </label>
            <span className="block text-sm text-muted-foreground">{t('general.spamActionHint')}</span>
          </span>
          <Select value={settings.data.spamAction} onValueChange={(spamAction) => save({ spamAction: spamAction as MailSettings['spamAction'] })}>
            <SelectTrigger id="spam-action" className="sm:w-48">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="spam_and_unsubscribe">{t('general.spamActionOn')}</SelectItem>
              <SelectItem value="just_spam">{t('general.spamActionOff')}</SelectItem>
              <SelectItem value="ask">{t('general.spamActionAsk')}</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="flex flex-col gap-3 rounded-lg border border-border p-4 sm:flex-row sm:items-center sm:justify-between">
          <span>
            <label htmlFor="delay-send" className="block text-sm font-medium">
              {t('general.delaySend')}
            </label>
            <span className="block text-sm text-muted-foreground">{t('general.delaySendHint')}</span>
          </span>
          <Select value={String(settings.data.delaySendSeconds)} onValueChange={(value) => save({ delaySendSeconds: Number(value) })}>
            <SelectTrigger id="delay-send" className="sm:w-48">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {[0, 5, 10, 20].map((seconds) => (
                <SelectItem key={seconds} value={String(seconds)}>
                  {seconds === 0 ? t('general.delaySendOff') : t('general.delaySendSeconds', { count: seconds })}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="flex flex-col gap-3 rounded-lg border border-border p-4 sm:flex-row sm:items-center sm:justify-between">
          <span>
            <span className="block text-sm font-medium">{t('general.mailtoTitle')}</span>
            <span className="block text-sm text-muted-foreground">{t('general.mailtoHint')}</span>
          </span>
          <Button
            variant="outline"
            onClick={() => (registerMailtoHandler() ? toast.success(t('general.mailtoAsked')) : toast.error(t('general.mailtoUnsupported')))}
          >
            {t('general.mailtoAction')}
          </Button>
        </div>
        <Setting
          label={t('general.confirmLink')}
          hint={t('general.confirmLinkHint')}
          checked={settings.data.confirmLink}
          onChange={(on) => save({ confirmLink: on })}
        />
        <Setting
          label={t('general.autoDelete')}
          hint={t('general.autoDeleteHint')}
          checked={settings.data.autoDeleteDays === 30}
          onChange={(on) => save({ autoDeleteDays: on ? 30 : 0 })}
        />
        <Setting
          label={t('general.almostAllMail')}
          hint={t('general.almostAllMailHint')}
          checked={settings.data.almostAllMail}
          onChange={(on) => save({ almostAllMail: on })}
        />
      </div>
      <NotificationSettings />
      <ContentSearchSettings />
      <section className="mt-8 space-y-3" aria-labelledby="images-heading">
        <h2 id="images-heading" className="text-sm font-medium">
          {t('remoteImages.settingsTitle')}
        </h2>
        <Setting
          label={t('remoteImages.proxyTitle')}
          hint={t('remoteImages.proxyHint')}
          checked={settings.data.imageProxy}
          onChange={(on) => save({ imageProxy: on })}
        />
        <Setting
          label={t('remoteImages.embeddedTitle')}
          hint={t('remoteImages.embeddedHint')}
          checked={settings.data.embeddedImages}
          onChange={(on) => save({ embeddedImages: on })}
        />
        <Setting
          label={t('remoteImages.metadataTitle')}
          hint={t('remoteImages.metadataHint')}
          checked={settings.data.removeImageMetadata}
          onChange={(on) => save({ removeImageMetadata: on })}
        />
        <div className="flex flex-col gap-3 rounded-lg border border-border p-4 sm:flex-row sm:items-center sm:justify-between">
          <span>
            <label htmlFor="remote-images" className="block text-sm font-medium">
              {t('remoteImages.setting')}
            </label>
            <span className="block text-sm text-muted-foreground">{t('remoteImages.settingHint')}</span>
          </span>
          <Select value={settings.data.remoteImages} onValueChange={(remoteImages) => save({ remoteImages: remoteImages as MailSettings['remoteImages'] })}>
            <SelectTrigger id="remote-images" className="sm:w-48">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="ask">{t('remoteImages.ask')}</SelectItem>
              <SelectItem value="always">{t('remoteImages.alwaysAll')}</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="rounded-lg border border-border p-4">
          <p className="text-sm font-medium">{t('remoteImages.sendersTitle')}</p>
          <p className="text-sm text-muted-foreground">{t('remoteImages.sendersHint')}</p>
          {imageSenders.data?.length ? (
            <ul className="mt-3 divide-y divide-border" aria-label={t('remoteImages.sendersTitle')}>
              {imageSenders.data.map((sender) => (
                <li key={sender.address} className="flex items-center gap-2 py-2 text-sm">
                  <span className="min-w-0 flex-1 truncate">{sender.address}</span>
                  <Button
                    variant="ghost"
                    size="sm"
                    aria-label={t('remoteImages.remove', { address: sender.address })}
                    disabled={removeImageSender.isPending}
                    onClick={() =>
                      removeImageSender.mutate(sender.address, {
                        onSuccess: () => toast.success(t('remoteImages.removed', { address: sender.address })),
                        onError: (error) => toast.error(apiErrorMessage(error, t('common.tryAgain'))),
                      })
                    }
                  >
                    {t('remoteImages.removeShort')}
                  </Button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-3 text-sm text-muted-foreground">{t('remoteImages.noSenders')}</p>
          )}
        </div>
      </section>
      <section className="mt-8 space-y-3" aria-labelledby="pgp-heading">
        <h2 id="pgp-heading" className="text-sm font-medium">
          {t('general.pgpTitle')}
        </h2>
        <p className="text-sm text-muted-foreground">{t('general.pgpHint')}</p>
        <Setting
          label={t('general.signOutside')}
          hint={t('general.signOutsideHint')}
          checked={settings.data.signOutside}
          onChange={(on) => save({ signOutside: on })}
        />
        <Setting
          label={t('general.attachPublicKey')}
          hint={t('general.attachPublicKeyHint')}
          checked={settings.data.attachPublicKey}
          onChange={(on) => save({ attachPublicKey: on })}
        />
        <div className="flex flex-col gap-3 rounded-lg border border-border p-4 sm:flex-row sm:items-center sm:justify-between">
          <span>
            <label htmlFor="pgp-scheme" className="block text-sm font-medium">
              {t('general.pgpScheme')}
            </label>
            <span className="block text-sm text-muted-foreground">{t('general.pgpSchemeHint')}</span>
          </span>
          <Select value={settings.data.pgpScheme} onValueChange={(pgpScheme) => save({ pgpScheme: pgpScheme as MailSettings['pgpScheme'] })}>
            <SelectTrigger id="pgp-scheme" className="sm:w-48" aria-label={t('general.pgpScheme')}>
              <SelectValue placeholder={t('general.pgpScheme')} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="pgp_mime">PGP/MIME</SelectItem>
              <SelectItem value="inline">{t('general.inline')}</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </section>
    </PageBody>
  )
}
