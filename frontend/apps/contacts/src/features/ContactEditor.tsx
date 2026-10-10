import { ImagePlus, Plus, X } from 'lucide-react'
import { useEffect, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { useContactGroups, useSaveContact } from '@kutup/contacts-core/api'
import { displayName, emptyDraft, type ContactAddress, type ContactDraft } from '@kutup/contacts-core/model'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { Textarea } from '@kutup/ui/components/textarea'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { ContactAvatar } from './ContactAvatar'
import { useEditor } from './editorState'

const EMAIL = /^[^\s@<>",;]+@[^\s@<>",;]+\.[^\s@<>",;]+$/
const LABELS = ['home', 'work', 'other'] as const
const PHONE_LABELS = ['cell', 'home', 'work', 'other'] as const
const PHOTO_SIZE = 256

/** Shrinks a picked image to a small square JPEG (data: URL), so cards stay small. */
async function photoFrom(file: File): Promise<string> {
  const bitmap = await createImageBitmap(file)
  const side = Math.min(bitmap.width, bitmap.height)
  const canvas = document.createElement('canvas')
  canvas.width = canvas.height = PHOTO_SIZE
  canvas.getContext('2d')!.drawImage(bitmap, (bitmap.width - side) / 2, (bitmap.height - side) / 2, side, side, 0, 0, PHOTO_SIZE, PHOTO_SIZE)
  bitmap.close()
  return canvas.toDataURL('image/jpeg', 0.85)
}

function Group({ title, children, onAdd, addLabel }: { title: string; children: ReactNode; onAdd: () => void; addLabel: string }) {
  return (
    <fieldset className="space-y-2">
      <legend className="text-sm font-medium">{title}</legend>
      {children}
      <Button type="button" variant="ghost" size="sm" onClick={onAdd}>
        <Plus />
        {addLabel}
      </Button>
    </fieldset>
  )
}

/** Radix Select has no empty value: "no type" is this. */
const NO_LABEL = '__none'

function LabelSelect({ value, options, onChange, aria }: { value?: string; options: readonly string[]; onChange: (value: string) => void; aria: string }) {
  const { t } = useTranslation()
  const known = !value || options.includes(value)
  return (
    <Select value={value || NO_LABEL} onValueChange={(next) => onChange(next === NO_LABEL ? '' : next)}>
      <SelectTrigger className="w-32 shrink-0" aria-label={aria}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={NO_LABEL}>{t('labels.none')}</SelectItem>
        {options.map((option) => (
          <SelectItem key={option} value={option}>{t(`labels.${option}`)}</SelectItem>
        ))}
        {known ? null : <SelectItem value={value}>{value}</SelectItem>}
      </SelectContent>
    </Select>
  )
}

function RemoveRow({ onClick, label }: { onClick: () => void; label: string }) {
  return (
    <Button type="button" variant="ghost" size="icon" onClick={onClick} aria-label={label} title={label}>
      <X />
    </Button>
  )
}

/** Creates or edits a contact in a dialog, as Proton's contact modal does. */
export function ContactEditorDialog() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const editor = useEditor()
  const groups = useContactGroups()
  const save = useSaveContact()
  const target = editor.target
  const [draft, setDraft] = useState<ContactDraft>(emptyDraft())
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!target) return
    setError(null)
    save.reset()
    if (target.kind === 'edit') setDraft(structuredClone(target.contact.draft))
    else setDraft({ ...emptyDraft(), emails: [{ address: target.email ?? '' }], groups: target.groupId ? [target.groupId] : [] })
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset once per opening
  }, [target])

  const update = (patch: Partial<ContactDraft>) => setDraft((now) => ({ ...now, ...patch }))
  const setAt = <K extends 'emails' | 'phones' | 'addresses' | 'urls'>(key: K, index: number, value: ContactDraft[K][number]) =>
    setDraft((now) => ({ ...now, [key]: now[key].map((item, i) => (i === index ? value : item)) }))
  const removeAt = (key: 'emails' | 'phones' | 'addresses' | 'urls', index: number) =>
    setDraft((now) => ({ ...now, [key]: (now[key] as unknown[]).filter((_, i) => i !== index) }))

  function submit() {
    const emails = draft.emails.filter((email) => email.address.trim())
    const bad = emails.find((email) => !EMAIL.test(email.address.trim()))
    if (bad) return setError(t('editor.badEmail', { address: bad.address.trim() }))
    const lower = emails.map((email) => email.address.trim().toLowerCase())
    if (new Set(lower).size !== lower.length) return setError(t('editor.duplicateEmail'))
    const cleaned: ContactDraft = {
      ...draft,
      emails,
      phones: draft.phones.filter((phone) => phone.value.trim()),
      addresses: draft.addresses.filter((a) => [a.street, a.locality, a.region, a.postcode, a.country].some((v) => v.trim())),
      urls: draft.urls.filter((url) => url.trim()),
    }
    if (!displayName(cleaned)) return setError(t('editor.needName'))
    setError(null)
    save.mutate(
      { draft: cleaned, existing: target?.kind === 'edit' ? target.contact : undefined },
      {
        onSuccess: (id) => {
          toast.success(target?.kind === 'edit' ? t('editor.saved') : t('editor.created'))
          editor.close()
          void navigate(`/c/${id}`)
        },
      },
    )
  }

  const emptyAddress: ContactAddress = { street: '', locality: '', region: '', postcode: '', country: '' }
  const saveError = save.error
    ? apiErrorMessage(save.error, t('editor.saveFailed')).includes('changed elsewhere')
      ? t('editor.conflict')
      : apiErrorMessage(save.error, t('editor.saveFailed'))
    : null

  return (
    <Dialog open={target !== null} onOpenChange={(open) => !open && editor.close()}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{target?.kind === 'edit' ? t('editor.editTitle') : t('editor.newTitle')}</DialogTitle>
          <DialogDescription>{t('editor.description')}</DialogDescription>
        </DialogHeader>
        <form
          className="mt-4 space-y-6"
          noValidate
          onSubmit={(e) => {
            e.preventDefault()
            submit()
          }}
        >
          <div className="flex items-center gap-4">
            <ContactAvatar draft={draft} size={80} />
            <div className="flex flex-wrap gap-2">
              <Button type="button" variant="outline" size="sm" asChild>
                <label className="cursor-pointer">
                  <ImagePlus />
                  {draft.photo ? t('editor.changePhoto') : t('editor.addPhoto')}
                  <input
                    type="file"
                    accept="image/*"
                    className="sr-only"
                    onChange={(e) => {
                      const file = e.target.files?.[0]
                      e.target.value = ''
                      if (file) void photoFrom(file).then((photo) => update({ photo })).catch(() => toast.error(t('editor.photoFailed')))
                    }}
                  />
                </label>
              </Button>
              {draft.photo ? (
                <Button type="button" variant="ghost" size="sm" onClick={() => update({ photo: '' })}>
                  {t('editor.removePhoto')}
                </Button>
              ) : null}
            </div>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="given">{t('fields.givenName')}</Label>
              <Input id="given" value={draft.givenName} onChange={(e) => update({ givenName: e.target.value })} autoFocus />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="family">{t('fields.familyName')}</Label>
              <Input id="family" value={draft.familyName} onChange={(e) => update({ familyName: e.target.value })} />
            </div>
            <div className="space-y-1.5 sm:col-span-2">
              <Label htmlFor="display">{t('fields.displayName')}</Label>
              <Input
                id="display"
                value={draft.name}
                placeholder={displayName({ ...draft, name: '' }) || undefined}
                onChange={(e) => update({ name: e.target.value })}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="org">{t('fields.organization')}</Label>
              <Input id="org" value={draft.organization} onChange={(e) => update({ organization: e.target.value })} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="title">{t('fields.title')}</Label>
              <Input id="title" value={draft.title} onChange={(e) => update({ title: e.target.value })} />
            </div>
          </div>

          <Group title={t('fields.emails')} addLabel={t('editor.addEmail')} onAdd={() => update({ emails: [...draft.emails, { address: '' }] })}>
            {draft.emails.map((email, i) => (
              <div key={i} className="flex gap-2">
                <Input
                  type="email"
                  inputMode="email"
                  value={email.address}
                  onChange={(e) => setAt('emails', i, { ...email, address: e.target.value })}
                  aria-label={t('fields.email')}
                  placeholder="name@example.com"
                />
                <LabelSelect value={email.label} options={LABELS} onChange={(label) => setAt('emails', i, { ...email, label: label || undefined })} aria={t('fields.label')} />
                <RemoveRow onClick={() => removeAt('emails', i)} label={t('editor.remove')} />
              </div>
            ))}
          </Group>

          <Group title={t('fields.phones')} addLabel={t('editor.addPhone')} onAdd={() => update({ phones: [...draft.phones, { value: '' }] })}>
            {draft.phones.map((phone, i) => (
              <div key={i} className="flex gap-2">
                <Input type="tel" inputMode="tel" value={phone.value} onChange={(e) => setAt('phones', i, { ...phone, value: e.target.value })} aria-label={t('fields.phone')} />
                <LabelSelect value={phone.label} options={PHONE_LABELS} onChange={(label) => setAt('phones', i, { ...phone, label: label || undefined })} aria={t('fields.label')} />
                <RemoveRow onClick={() => removeAt('phones', i)} label={t('editor.remove')} />
              </div>
            ))}
          </Group>

          <Group title={t('fields.addresses')} addLabel={t('editor.addAddress')} onAdd={() => update({ addresses: [...draft.addresses, { ...emptyAddress }] })}>
            {draft.addresses.map((address, i) => (
              <div key={i} className="space-y-2 rounded-md border border-border p-3">
                <div className="flex gap-2">
                  <Input value={address.street} onChange={(e) => setAt('addresses', i, { ...address, street: e.target.value })} aria-label={t('fields.street')} placeholder={t('fields.street')} />
                  <LabelSelect value={address.label} options={LABELS} onChange={(label) => setAt('addresses', i, { ...address, label: label || undefined })} aria={t('fields.label')} />
                  <RemoveRow onClick={() => removeAt('addresses', i)} label={t('editor.remove')} />
                </div>
                <div className="grid gap-2 sm:grid-cols-2">
                  <Input value={address.postcode} onChange={(e) => setAt('addresses', i, { ...address, postcode: e.target.value })} aria-label={t('fields.postcode')} placeholder={t('fields.postcode')} />
                  <Input value={address.locality} onChange={(e) => setAt('addresses', i, { ...address, locality: e.target.value })} aria-label={t('fields.locality')} placeholder={t('fields.locality')} />
                  <Input value={address.region} onChange={(e) => setAt('addresses', i, { ...address, region: e.target.value })} aria-label={t('fields.region')} placeholder={t('fields.region')} />
                  <Input value={address.country} onChange={(e) => setAt('addresses', i, { ...address, country: e.target.value })} aria-label={t('fields.country')} placeholder={t('fields.country')} />
                </div>
              </div>
            ))}
          </Group>

          <Group title={t('fields.urls')} addLabel={t('editor.addUrl')} onAdd={() => update({ urls: [...draft.urls, ''] })}>
            {draft.urls.map((url, i) => (
              <div key={i} className="flex gap-2">
                <Input type="url" inputMode="url" value={url} onChange={(e) => setAt('urls', i, e.target.value)} aria-label={t('fields.url')} placeholder="https://" />
                <RemoveRow onClick={() => removeAt('urls', i)} label={t('editor.remove')} />
              </div>
            ))}
          </Group>

          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="birthday">{t('fields.birthday')}</Label>
              {draft.birthday.startsWith('--') ? (
                <div className="flex gap-2">
                  <Input id="birthday" value={draft.birthday} readOnly />
                  <RemoveRow onClick={() => update({ birthday: '' })} label={t('editor.remove')} />
                </div>
              ) : (
                <Input id="birthday" type="date" value={draft.birthday} onChange={(e) => update({ birthday: e.target.value })} />
              )}
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="notes">{t('fields.notes')}</Label>
            <Textarea id="notes" rows={4} value={draft.notes} onChange={(e) => update({ notes: e.target.value })} />
          </div>

          {(groups.data ?? []).length > 0 ? (
            <fieldset className="space-y-2">
              <legend className="text-sm font-medium">{t('fields.groups')}</legend>
              <div className="flex flex-wrap gap-x-4 gap-y-2">
                {groups.data!.map((group) => (
                  <label key={group.id} className="flex items-center gap-2 text-sm">
                    <Checkbox
                      checked={draft.groups.includes(group.id)}
                      onCheckedChange={(on) =>
                        update({ groups: on === true ? [...draft.groups, group.id] : draft.groups.filter((id) => id !== group.id) })
                      }
                    />
                    <span aria-hidden className="size-2.5 rounded-full" style={{ background: group.color }} />
                    {group.name}
                  </label>
                ))}
              </div>
            </fieldset>
          ) : null}

          {error || saveError ? <Alert variant="error">{error ?? saveError}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => editor.close()}>{t('common.cancel')}</Button>
            <Button type="submit" loading={save.isPending}>{t('common.save')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
