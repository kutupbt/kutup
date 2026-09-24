import { Camera, Copy, Loader2, Trash2 } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { contactUri } from '@kutup/chat-core/identity'
import { Button } from '@kutup/ui/components/button'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { refreshChat, useChat } from '../../app/chatStore'
import { Avatar } from '../../components/Avatar'
import { normalizeAvatar } from '../../lib/avatar'
import { chatErrorMessage } from '../../lib/errors'
import { SettingsSection } from './SettingsPage'

/**
 * Your chat profile (name and picture, encrypted and shared only with
 * people you message or accept, as in Signal) and your address to give out,
 * as text and as a QR code.
 */
export function ProfileSettings() {
  const { t } = useTranslation()
  const { service, snapshot, self } = useChat()
  const profile = snapshot.profile
  const [name, setName] = useState(profile?.displayName ?? '')
  const [avatar, setAvatar] = useState<{ base64?: string; contentType?: string }>({
    base64: profile?.avatar,
    contentType: profile?.avatarContentType,
  })
  const [processing, setProcessing] = useState(false)
  const [saving, setSaving] = useState(false)
  const file = useRef<HTMLInputElement>(null)

  // Another device (or tab) saved a new profile: show it.
  useEffect(() => {
    setName(profile?.displayName ?? '')
    setAvatar({ base64: profile?.avatar, contentType: profile?.avatarContentType })
  }, [profile?.revision, profile?.displayName, profile?.avatar, profile?.avatarContentType])

  async function choose(chosen: File | undefined) {
    if (!chosen) return
    setProcessing(true)
    try {
      const normalized = await normalizeAvatar(chosen)
      setAvatar({ base64: normalized.base64, contentType: normalized.contentType })
    } catch {
      toast.error(t('chat.profile.avatarError'))
    } finally {
      setProcessing(false)
      if (file.current) file.current.value = ''
    }
  }

  async function save(event: FormEvent) {
    event.preventDefault()
    if (!service || !name.trim() || saving || processing) return
    setSaving(true)
    try {
      await service.setProfile(name.trim(), avatar.base64, avatar.contentType)
      await refreshChat()
      toast.success(t('chat.profile.saved'))
    } catch (error) {
      toast.error(chatErrorMessage(error, t))
    } finally {
      setSaving(false)
    }
  }

  const changed =
    name.trim() !== (profile?.displayName ?? '') || avatar.base64 !== profile?.avatar
  const address = self!.address

  return (
    <div className="space-y-10">
      <SettingsSection title={t('chat.profile.title')} description={t('chat.profile.description')}>
        <form onSubmit={(e) => void save(e)} className="max-w-md space-y-5">
          <div className="flex items-center gap-4">
            <Avatar name={name || address} image={avatar.base64} contentType={avatar.contentType} size={80} />
            <div className="flex flex-col gap-2">
              <input ref={file} type="file" accept="image/png,image/jpeg,image/webp" hidden onChange={(e) => void choose(e.target.files?.[0])} />
              <Button type="button" size="sm" variant="outline" disabled={processing || saving} onClick={() => file.current?.click()}>
                {processing ? <Loader2 className="animate-spin" /> : <Camera />}
                {t('chat.profile.changeAvatar')}
              </Button>
              {avatar.base64 ? (
                <Button type="button" size="sm" variant="ghost" disabled={saving} onClick={() => setAvatar({})}>
                  <Trash2 />
                  {t('chat.profile.removeAvatar')}
                </Button>
              ) : null}
            </div>
          </div>
          <p className="text-xs text-muted-foreground">{t('chat.profile.avatarHint')}</p>
          <Field label={t('chat.profile.displayName')}>
            {(props) => <Input {...props} value={name} onChange={(e) => setName(e.target.value)} maxLength={80} required autoComplete="name" />}
          </Field>
          <p className="text-xs text-muted-foreground">{t('chat.profile.visibility')}</p>
          <Button type="submit" disabled={!name.trim() || !changed || saving || processing}>
            {saving ? <Loader2 className="animate-spin" /> : null}
            {t('common.save')}
          </Button>
        </form>
      </SettingsSection>

      <SettingsSection title={t('chat.contact.title')} description={t('chat.contact.description')}>
        <div className="flex flex-col items-start gap-4 sm:flex-row sm:items-center">
          <div className="rounded-xl border border-border bg-white p-3">
            <QRCodeSVG value={contactUri(self!.account)} size={168} aria-label={t('chat.contact.qr')} />
          </div>
          <div className="space-y-3">
            <code className="block break-all rounded-md bg-muted px-3 py-2 font-mono text-sm">{address}</code>
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                void navigator.clipboard
                  .writeText(address)
                  .then(() => toast.success(t('chat.contact.copied')))
                  .catch(() => toast.error(t('chat.message.copyFailed')))
              }}
            >
              <Copy />
              {t('chat.contact.copy')}
            </Button>
          </div>
        </div>
      </SettingsSection>
    </div>
  )
}
