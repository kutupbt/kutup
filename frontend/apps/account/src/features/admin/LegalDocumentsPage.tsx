import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { Card, CardContent } from '@kutup/ui/components/card'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Mono } from '@kutup/ui/components/mono'
import { PageBody, PageHeader, Section } from '@kutup/ui/components/page'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { formatInstant } from '@kutup/ui/lib/format'
import { documentName } from '../auth/legal'
import { useLegalDocuments, usePublishDocument } from './api'

/** Kinds the pages know by name; any other lowercase kind works too. */
const KNOWN_KINDS = ['terms', 'privacy_notice', 'federation_abroad', 'marketing']
const HEX64 = /^[0-9a-fA-F]{64}$/

/**
 * Administration → Legal documents (docs/plans/server-personal-data.md, A3):
 * the operator's texts, by version. The text lives where the URL says; the
 * server keeps the SHA-256 of the exact text shown. A version is never
 * edited: a change is a new version, which sign-ins then ask to confirm when
 * it is required.
 */
export function LegalDocumentsPage() {
  const { t, i18n } = useTranslation()
  const documents = useLegalDocuments()
  const publish = usePublishDocument()
  const [form, setForm] = useState({ kind: '', version: '', language: i18n.language.split('-')[0], url: '', sha256: '', requiredAtSignup: false })
  const [error, setError] = useState<string | null>(null)
  const set = (patch: Partial<typeof form>) => setForm((f) => ({ ...f, ...patch }))

  function submit(event: FormEvent) {
    event.preventDefault()
    if (!form.kind.trim() || !form.version.trim() || !form.url.trim() || !HEX64.test(form.sha256.trim())) {
      setError(t('admin.legal.incomplete'))
      return
    }
    setError(null)
    publish.mutate(form, {
      onSuccess: () => {
        toast.success(t('admin.legal.published'))
        set({ version: '', url: '', sha256: '' })
      },
      onError: (err) => setError(apiErrorMessage(err, t('admin.legal.failed'))),
    })
  }

  return (
    <PageBody width="prose">
      <PageHeader title={t('admin.legal.title')} description={t('admin.legal.description')} />
      <Section title={t('admin.legal.publishTitle')} description={t('admin.legal.publishHint')}>
        <Card>
          <CardContent className="p-5">
            <form className="grid gap-4 sm:grid-cols-2" onSubmit={submit} noValidate>
              <Field label={t('admin.legal.kind')} description={t('admin.legal.kindHint')} required>
                {(field) => (
                  <>
                    <Input {...field} value={form.kind} list="legal-kinds" onChange={(e) => set({ kind: e.target.value.toLowerCase() })} />
                    <datalist id="legal-kinds">
                      {KNOWN_KINDS.map((kind) => (
                        <option key={kind} value={kind} />
                      ))}
                    </datalist>
                  </>
                )}
              </Field>
              <Field label={t('admin.legal.version')} required>
                {(field) => <Input {...field} value={form.version} maxLength={40} onChange={(e) => set({ version: e.target.value })} />}
              </Field>
              <Field label={t('admin.legal.language')} description={t('admin.legal.languageHint')} required>
                {(field) => <Input {...field} value={form.language} maxLength={16} onChange={(e) => set({ language: e.target.value })} />}
              </Field>
              <Field label={t('admin.legal.url')} required>
                {(field) => <Input {...field} type="url" value={form.url} onChange={(e) => set({ url: e.target.value })} />}
              </Field>
              <div className="sm:col-span-2">
                <Field label={t('admin.legal.sha256')} description={t('admin.legal.sha256Hint')} required>
                  {(field) => <Input {...field} value={form.sha256} spellCheck={false} className="font-mono" onChange={(e) => set({ sha256: e.target.value.trim() })} />}
                </Field>
              </div>
              <label className="flex items-start gap-2 text-sm sm:col-span-2">
                <Checkbox className="mt-0.5" checked={form.requiredAtSignup} onCheckedChange={(v) => set({ requiredAtSignup: v === true })} />
                <span>{t('admin.legal.required')}</span>
              </label>
              {error ? (
                <div className="sm:col-span-2">
                  <Alert variant="error">{error}</Alert>
                </div>
              ) : null}
              <div className="sm:col-span-2">
                <Button type="submit" loading={publish.isPending}>
                  {t('admin.legal.publish')}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </Section>
      <Section title={t('admin.legal.versions')}>
        {documents.isPending ? <LoadingPanel label={t('common.loading')} /> : null}
        {documents.isError ? <Alert variant="error">{apiErrorMessage(documents.error, t('common.tryAgain'))}</Alert> : null}
        {documents.data && documents.data.length === 0 ? (
          <EmptyState title={t('admin.legal.noneTitle')} description={t('admin.legal.noneDescription')} />
        ) : null}
        {documents.data && documents.data.length > 0 ? (
          <Card className="divide-y divide-border p-0">
            {documents.data.map((document) => (
              <CardContent key={document.id} className="space-y-1 p-4 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{documentName(t, document.kind)}</span>
                  <Badge variant="neutral">{document.version}</Badge>
                  <Badge variant="neutral">{document.language}</Badge>
                  {document.requiredAtSignup ? <Badge>{t('admin.legal.requiredBadge')}</Badge> : null}
                  <span className="ml-auto text-muted-foreground">{formatInstant(document.publishedAt, i18n.language)}</span>
                </div>
                <a href={document.url} target="_blank" rel="noopener noreferrer" className="block truncate text-primary hover:underline">
                  {document.url}
                </a>
                <Mono className="block truncate text-xs text-muted-foreground">{document.sha256}</Mono>
              </CardContent>
            ))}
          </Card>
        ) : null}
      </Section>
    </PageBody>
  )
}
