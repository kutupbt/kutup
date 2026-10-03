import { Camera, Copy, Loader2, Lock, Trash2 } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { PROFILE_ABOUT_MAX_CHARS } from '@kutup/chat-core/types'
import { contactUri } from '@kutup/chat-core/identity'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Avatar } from '@kutup/ui/components/avatar'
import { Button } from '@kutup/ui/components/button'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { PageBody, PageHeader, Section } from '@kutup/ui/components/page'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { normalizeAvatar } from '@kutup/ui/lib/avatar'
import { PresenceColourPicker } from './PresenceColourPicker'
import { useAccountAddress, useOwnProfile, useSaveProfile } from './profile'

/**
 * The account's one profile: picture, name and "about", end-to-end
 * encrypted and shown to the people you chat with; the presence colour for
 * editing together; and your address to give out (docs/plans/unified-profile.md).
 */
export function ProfilePage() {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const address = useAccountAddress()
  const profile = useOwnProfile()
  const save = useSaveProfile()
  const view = profile.data?.view ?? null
  const fallbackName = session.username ?? ''
  const [name, setName] = useState('')
  const [about, setAbout] = useState('')
  const [avatar, setAvatar] = useState<{ base64?: string; contentType?: string }>({})
  const [processing, setProcessing] = useState(false)
  const file = useRef<HTMLInputElement>(null)

  // What the server holds (on load, and after another device saved).
  const loaded = profile.data !== undefined
  useEffect(() => {
    if (!loaded) return
    setName(view?.displayName ?? fallbackName)
    setAbout(view?.about ?? '')
    setAvatar({ base64: view?.avatar, contentType: view?.avatarContentType })
  }, [loaded, view?.revision, view?.displayName, view?.about, view?.avatar, view?.avatarContentType, fallbackName])

  async function choose(chosen: File | undefined) {
    if (!chosen) return
    setProcessing(true)
    try {
      const normalized = await normalizeAvatar(chosen)
      setAvatar({ base64: normalized.base64, contentType: normalized.contentType })
    } catch {
      toast.error(t('settings.profile.avatarError'))
    } finally {
      setProcessing(false)
      if (file.current) file.current.value = ''
    }
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!name.trim() || save.isPending || processing) return
    try {
      await save.mutateAsync({
        displayName: name.trim(),
        ...(about.trim() ? { about: about.trim() } : {}),
        ...(avatar.base64 ? { avatar: avatar.base64, avatarContentType: avatar.contentType } : {}),
      })
      toast.success(t('settings.profile.saved'))
    } catch (error) {
      toast.error(apiErrorMessage(error, t('settings.profile.saveFailed')))
    }
  }

  const aboutTooLong = [...about.trim()].length > PROFILE_ABOUT_MAX_CHARS
  const changed =
    name.trim() !== (view?.displayName ?? fallbackName) ||
    about.trim() !== (view?.about ?? '') ||
    avatar.base64 !== view?.avatar ||
    (view === null && name.trim().length > 0)

  return (
    <PageBody width="prose">
      <PageHeader title={t('settings.profile.title')} description={t('settings.profile.description')} />

      <Section title={t('settings.profile.who')}>
        {profile.isError ? (
          <Alert variant="error">{apiErrorMessage(profile.error, t('common.tryAgain'))}</Alert>
        ) : !loaded ? (
          <Skeleton className="h-48 w-full" />
        ) : (
          <form onSubmit={(event) => void submit(event)} className="space-y-5" data-testid="account-profile-form">
            <div className="flex items-center gap-4">
              <Avatar name={name || fallbackName} image={avatar.base64} contentType={avatar.contentType} size={80} />
              <div className="flex flex-wrap gap-2">
                <input
                  ref={file}
                  type="file"
                  accept="image/png,image/jpeg,image/webp"
                  className="hidden"
                  onChange={(event) => void choose(event.target.files?.[0])}
                  data-testid="account-profile-avatar-input"
                />
                <Button type="button" variant="outline" size="sm" disabled={processing} onClick={() => file.current?.click()}>
                  {processing ? <Loader2 className="animate-spin" /> : <Camera />}
                  {t('settings.profile.changeAvatar')}
                </Button>
                {avatar.base64 ? (
                  <Button type="button" variant="ghost" size="sm" onClick={() => setAvatar({})}>
                    <Trash2 />
                    {t('settings.profile.removeAvatar')}
                  </Button>
                ) : null}
              </div>
            </div>
            <Field label={t('settings.profile.name')}>
              {(props) => (
                <Input {...props} value={name} maxLength={80} onChange={(e) => setName(e.target.value)} data-testid="account-profile-name" />
              )}
            </Field>
            <Field
              label={t('settings.profile.about')}
              error={aboutTooLong ? t('settings.profile.aboutTooLong', { max: PROFILE_ABOUT_MAX_CHARS }) : undefined}
            >
              {(props) => (
                <Input
                  {...props}
                  value={about}
                  onChange={(e) => setAbout(e.target.value)}
                  placeholder={t('settings.profile.aboutPlaceholder')}
                  data-testid="account-profile-about"
                />
              )}
            </Field>
            <p className="flex items-start gap-2 text-sm text-muted-foreground">
              <Lock className="mt-0.5 size-4 shrink-0" aria-hidden />
              {t('settings.profile.visibility')}
            </p>
            <Button type="submit" disabled={!changed || !name.trim() || aboutTooLong || save.isPending || processing} data-testid="account-profile-save">
              {save.isPending ? <Loader2 className="animate-spin" /> : null}
              {t('settings.profile.save')}
            </Button>
          </form>
        )}
      </Section>

      <Section title={t('settings.account.colour')} description={t('settings.account.colourDescription')}>
        <PresenceColourPicker />
      </Section>

      {address ? (
        <Section title={t('settings.profile.address')} description={t('settings.profile.addressDescription')}>
          <div className="flex flex-col items-start gap-4 sm:flex-row sm:items-center">
            <div className="rounded-xl border border-border bg-white p-3">
              <QRCodeSVG value={contactUri({ username: address.split('@')[0], server: address.split('@')[1] })} size={144} aria-label={t('settings.profile.qr')} />
            </div>
            <div className="space-y-3">
              <code className="block break-all rounded-md bg-muted px-3 py-2 font-mono text-sm" data-testid="account-profile-address">{address}</code>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => {
                  void navigator.clipboard
                    .writeText(address)
                    .then(() => toast.success(t('settings.profile.copied')))
                    .catch(() => toast.error(t('settings.profile.copyFailed')))
                }}
              >
                <Copy />
                {t('settings.profile.copy')}
              </Button>
            </div>
          </div>
        </Section>
      ) : null}
    </PageBody>
  )
}
