import { Plus, Trash2 } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { PasswordInput } from '@kutup/ui/components/password-input'
import { Textarea } from '@kutup/ui/components/textarea'
import { otpFieldValue } from '../lib/otp'
import { strengthOf } from '../lib/generator'
import type { EntryInput, EntryView, FieldView } from '../vault/types'
import { fieldValue, STANDARD_FIELDS } from '../vault/types'
import { PasswordGenerator } from './PasswordGenerator'

const OTP_FIELD = 'otp'

interface Draft {
  title: string
  userName: string
  password: string
  url: string
  notes: string
  otp: string
  custom: FieldView[]
  tags: string
  expires: boolean
  expiry: string
}

function draftOf(entry: EntryView | null, defaultUserName: string): Draft {
  if (!entry) {
    return { title: '', userName: defaultUserName, password: '', url: '', notes: '', otp: '', custom: [], tags: '', expires: false, expiry: '' }
  }
  return {
    title: fieldValue(entry, 'Title'),
    userName: fieldValue(entry, 'UserName'),
    password: fieldValue(entry, 'Password'),
    url: fieldValue(entry, 'URL'),
    notes: fieldValue(entry, 'Notes'),
    otp: fieldValue(entry, OTP_FIELD),
    custom: entry.fields.filter((f) => !(STANDARD_FIELDS as readonly string[]).includes(f.key) && f.key !== OTP_FIELD),
    tags: entry.tags.join(', '),
    expires: entry.expires,
    // datetime-local wants minutes, local time.
    expiry: entry.expiry ? toLocalInput(entry.expiry) : '',
  }
}

function toLocalInput(utc: string): string {
  const date = new Date(utc)
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000)
  return local.toISOString().slice(0, 16)
}

/** An entry's editable data from the form; throws a message key when it is invalid. */
function inputOf(draft: Draft, original: EntryView | null): EntryInput {
  const otp = otpFieldValue(draft.otp, draft.title)
  if (otp === null) throw new Error('entry.otpInvalid')
  const names = new Set<string>()
  for (const field of draft.custom) {
    const key = field.key.trim()
    if (!key) throw new Error('entry.fieldNameMissing')
    if ((STANDARD_FIELDS as readonly string[]).includes(key) || key === OTP_FIELD || names.has(key)) throw new Error('entry.fieldNameTaken')
    names.add(key)
  }
  if (draft.expires && !draft.expiry) throw new Error('entry.expiryMissing')
  const protectedNow = (key: string) => original?.fields.find((f) => f.key === key)?.protected ?? false
  const fields: FieldView[] = [
    { key: 'Title', value: draft.title, protected: protectedNow('Title') },
    { key: 'UserName', value: draft.userName, protected: protectedNow('UserName') },
    { key: 'Password', value: draft.password, protected: true },
    { key: 'URL', value: draft.url, protected: protectedNow('URL') },
    { key: 'Notes', value: draft.notes, protected: protectedNow('Notes') },
    ...draft.custom.map((f) => ({ ...f, key: f.key.trim() })),
  ]
  if (otp) fields.push({ key: OTP_FIELD, value: otp, protected: true })
  return {
    fields,
    tags: draft.tags
      .split(',')
      .map((tag) => tag.trim())
      .filter(Boolean),
    icon: original?.icon ?? null,
    foregroundColor: original?.foregroundColor ?? null,
    backgroundColor: original?.backgroundColor ?? null,
    overrideUrl: original?.overrideUrl ?? '',
    qualityCheck: original?.qualityCheck ?? true,
    expires: draft.expires,
    expiry: draft.expires && draft.expiry ? new Date(draft.expiry).toISOString().replace(/\.\d{3}Z$/, 'Z') : null,
  }
}

/** Creates or edits an entry, with every field KeePassXC keeps that people edit. */
export function EntryEditor({
  open,
  onOpenChange,
  entry,
  defaultUserName,
  onSave,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The entry edited; `null` makes a new one. */
  entry: EntryView | null
  defaultUserName: string
  onSave: (input: EntryInput) => Promise<void>
}) {
  const { t } = useTranslation()
  const [draft, setDraft] = useState<Draft>(() => draftOf(entry, defaultUserName))
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  useEffect(() => {
    if (!open) return
    setDraft(draftOf(entry, defaultUserName))
    setError(null)
  }, [open, entry, defaultUserName])

  const set = (patch: Partial<Draft>) => setDraft((now) => ({ ...now, ...patch }))
  const setCustom = (index: number, patch: Partial<FieldView>) =>
    setDraft((now) => ({ ...now, custom: now.custom.map((f, i) => (i === index ? { ...f, ...patch } : f)) }))

  const submit = async () => {
    let input: EntryInput
    try {
      input = inputOf(draft, entry)
    } catch (invalid) {
      setError(t((invalid as Error).message))
      return
    }
    setPending(true)
    setError(null)
    try {
      await onSave(input)
      onOpenChange(false)
    } catch {
      setError(t('entry.saveFailed'))
    } finally {
      setPending(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !pending && onOpenChange(next)}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{entry ? t('entry.editTitle') : t('entry.newTitle')}</DialogTitle>
        </DialogHeader>
        <form
          className="mt-4 space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            void submit()
          }}
        >
          <Field label={t('entry.title')}>
            {(field) => <Input {...field} value={draft.title} onChange={(e) => set({ title: e.target.value })} autoFocus />}
          </Field>
          <Field label={t('entry.userName')}>
            {(field) => <Input {...field} value={draft.userName} onChange={(e) => set({ userName: e.target.value })} autoComplete="off" />}
          </Field>
          <Field label={t('entry.password')} description={draft.password ? t(`strength.${strengthOf(draft.password)}`) : undefined}>
            {(field) => (
              <div className="flex gap-2">
                <PasswordInput {...field} className="flex-1" value={draft.password} onChange={(e) => set({ password: e.target.value })} autoComplete="new-password" />
                <PasswordGenerator onUse={(password) => set({ password })} />
              </div>
            )}
          </Field>
          <Field label={t('entry.url')}>
            {(field) => <Input {...field} type="url" inputMode="url" value={draft.url} onChange={(e) => set({ url: e.target.value })} placeholder="https://" />}
          </Field>
          <Field label={t('entry.otp')} description={t('entry.otpDescription')}>
            {(field) => <Input {...field} value={draft.otp} onChange={(e) => set({ otp: e.target.value })} autoComplete="off" spellCheck={false} />}
          </Field>
          <Field label={t('entry.notes')}>
            {(field) => <Textarea {...field} rows={4} value={draft.notes} onChange={(e) => set({ notes: e.target.value })} />}
          </Field>
          <fieldset className="space-y-2">
            <legend className="text-sm font-medium">{t('entry.customFields')}</legend>
            {draft.custom.map((f, index) => (
              <div key={index} className="flex flex-wrap items-center gap-2 rounded-md border border-border p-2">
                <Input
                  aria-label={t('entry.fieldName')}
                  placeholder={t('entry.fieldName')}
                  className="min-w-32 flex-1"
                  value={f.key}
                  onChange={(e) => setCustom(index, { key: e.target.value })}
                />
                {f.protected ? (
                  <PasswordInput
                    aria-label={t('entry.fieldValue')}
                    placeholder={t('entry.fieldValue')}
                    className="min-w-40 flex-[2]"
                    value={f.value}
                    onChange={(e) => setCustom(index, { value: e.target.value })}
                  />
                ) : (
                  <Input
                    aria-label={t('entry.fieldValue')}
                    placeholder={t('entry.fieldValue')}
                    className="min-w-40 flex-[2]"
                    value={f.value}
                    onChange={(e) => setCustom(index, { value: e.target.value })}
                  />
                )}
                <div className="flex items-center gap-1.5">
                  <Checkbox id={`field-protected-${index}`} checked={f.protected} onCheckedChange={(v) => setCustom(index, { protected: v === true })} />
                  <Label htmlFor={`field-protected-${index}`} className="text-xs font-normal">
                    {t('entry.fieldProtected')}
                  </Label>
                </div>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  aria-label={t('entry.removeField')}
                  onClick={() => setDraft((now) => ({ ...now, custom: now.custom.filter((_, i) => i !== index) }))}
                >
                  <Trash2 />
                </Button>
              </div>
            ))}
            <Button type="button" variant="outline" size="sm" onClick={() => set({ custom: [...draft.custom, { key: '', value: '', protected: false }] })}>
              <Plus />
              {t('entry.addField')}
            </Button>
          </fieldset>
          <Field label={t('entry.tags')} description={t('entry.tagsDescription')}>
            {(field) => <Input {...field} value={draft.tags} onChange={(e) => set({ tags: e.target.value })} />}
          </Field>
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Checkbox id="entry-expires" checked={draft.expires} onCheckedChange={(v) => set({ expires: v === true })} />
              <Label htmlFor="entry-expires">{t('entry.expires')}</Label>
            </div>
            {draft.expires ? (
              <Input type="datetime-local" aria-label={t('entry.expiry')} value={draft.expiry} onChange={(e) => set({ expiry: e.target.value })} />
            ) : null}
          </div>
          {error ? <Alert variant="error">{error}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={pending}>
              {t('common.save')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
