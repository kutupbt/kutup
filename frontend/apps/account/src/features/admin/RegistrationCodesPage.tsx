import { Copy, Link2, Plus, Users } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { CreatedRegistrationCode, RegistrationCode } from '@kutup/session/api-types'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Mono } from '@kutup/ui/components/mono'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@kutup/ui/components/table'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { copyText } from '@kutup/ui/lib/clipboard'
import { formatInstant } from '@kutup/ui/lib/format'
import { useCreateRegistrationCode, useRegistrationCodes, useRegistrationCodeUses, useRevokeRegistrationCode } from './api'
import { Choice } from './federation/Choice'

// Referral codes (docs/plans/registration-codes.md): what admits a sign-up
// when the registration mode asks for one. A code is shown once, when it is
// made; afterwards only its last four characters.

const EXPIRIES = ['day', 'week', 'month', 'never'] as const
type Expiry = (typeof EXPIRIES)[number]
const EXPIRY_MS: Record<Exclude<Expiry, 'never'>, number> = {
  day: 24 * 3600 * 1000,
  week: 7 * 24 * 3600 * 1000,
  month: 30 * 24 * 3600 * 1000,
}
const USE_LIMITS = ['one', 'number', 'unlimited'] as const
type UseLimit = (typeof USE_LIMITS)[number]
const MAX_USES = 100_000

/** The sign-up link for a code: in the fragment, so it never reaches a server's logs. */
function signUpLink(code: string): string {
  return `${window.location.origin}/register#code=${encodeURIComponent(code)}`
}

export function RegistrationCodesPage() {
  const { t, i18n } = useTranslation()
  const codes = useRegistrationCodes()
  const revoke = useRevokeRegistrationCode()
  const [creating, setCreating] = useState(false)
  const [made, setMade] = useState<CreatedRegistrationCode | null>(null)
  const [revoking, setRevoking] = useState<RegistrationCode | null>(null)
  const [showingUses, setShowingUses] = useState<RegistrationCode | null>(null)
  const lang = i18n.language

  if (codes.isPending) return <LoadingPanel label={t('common.loading')} />

  return (
    <PageBody>
      <PageHeader
        title={t('admin.codes.title')}
        description={t('admin.codes.description')}
        actions={
          <Button onClick={() => setCreating(true)}>
            <Plus aria-hidden />
            {t('admin.codes.new')}
          </Button>
        }
      />
      {codes.isError ? <Alert variant="error">{apiErrorMessage(codes.error, t('common.tryAgain'))}</Alert> : null}
      {codes.data && codes.data.length === 0 ? (
        <EmptyState title={t('admin.codes.emptyTitle')} description={t('admin.codes.emptyDescription')} />
      ) : null}
      {codes.data && codes.data.length > 0 ? (
        <Table aria-label={t('admin.codes.title')}>
          <TableHeader>
            <TableRow>
              <TableHead>{t('admin.codes.columns.code')}</TableHead>
              <TableHead>{t('admin.codes.columns.note')}</TableHead>
              <TableHead>{t('admin.codes.columns.uses')}</TableHead>
              <TableHead>{t('admin.codes.columns.expires')}</TableHead>
              <TableHead>{t('admin.codes.columns.state')}</TableHead>
              <TableHead>
                <span className="sr-only">{t('admin.codes.columns.actions')}</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {codes.data.map((code) => (
              <TableRow key={code.id}>
                <TableCell>
                  <Mono>…{code.hint}</Mono>
                  <div className="text-xs text-muted-foreground">
                    {t('admin.codes.madeBy', { name: code.createdBy ?? t('admin.activity.deletedUser'), when: formatInstant(code.createdAt, lang) })}
                  </div>
                </TableCell>
                <TableCell className="max-w-56 truncate">{code.note || '—'}</TableCell>
                <TableCell>
                  {code.maxUses === null ? t('admin.codes.usesUnlimited', { uses: code.uses }) : t('admin.codes.usesOf', { uses: code.uses, max: code.maxUses })}
                </TableCell>
                <TableCell>{code.expiresAt ? formatInstant(code.expiresAt, lang) : t('admin.codes.never')}</TableCell>
                <TableCell>
                  <Badge variant={code.state === 'active' ? 'ok' : 'neutral'}>{t(`admin.codes.state.${code.state}`)}</Badge>
                </TableCell>
                <TableCell className="whitespace-nowrap text-right">
                  <Button variant="ghost" size="sm" disabled={code.uses === 0} onClick={() => setShowingUses(code)} aria-label={t('admin.codes.usedByFor', { hint: code.hint })}>
                    <Users aria-hidden />
                    {t('admin.codes.usedBy')}
                  </Button>
                  {code.state === 'active' ? (
                    <Button variant="ghost" size="sm" onClick={() => setRevoking(code)} aria-label={t('admin.codes.revokeFor', { hint: code.hint })}>
                      {t('admin.codes.revoke')}
                    </Button>
                  ) : null}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : null}

      {creating ? (
        <CreateCodeDialog
          onClose={() => setCreating(false)}
          onMade={(code) => {
            setCreating(false)
            setMade(code)
          }}
        />
      ) : null}
      {made ? <MadeCodeDialog code={made} onClose={() => setMade(null)} /> : null}
      {showingUses ? <UsesDialog code={showingUses} onClose={() => setShowingUses(null)} /> : null}
      {revoking ? (
        <ConfirmDestructive
          open
          onOpenChange={(open) => {
            if (!open) {
              setRevoking(null)
              revoke.reset()
            }
          }}
          title={t('admin.codes.revokeTitle')}
          description={t('admin.codes.revokeDescription', { hint: revoking.hint })}
          submit={t('admin.codes.revoke')}
          pending={revoke.isPending}
          error={revoke.error}
          errorFallback={t('admin.codes.revokeFailed')}
          onConfirm={() =>
            revoke.mutate(revoking.id, {
              onSuccess: () => {
                toast.success(t('admin.codes.revoked'))
                setRevoking(null)
              },
            })
          }
        />
      ) : null}
    </PageBody>
  )
}

function CreateCodeDialog({ onClose, onMade }: { onClose: () => void; onMade: (code: CreatedRegistrationCode) => void }) {
  const { t } = useTranslation()
  const create = useCreateRegistrationCode()
  const [note, setNote] = useState('')
  const [expiry, setExpiry] = useState<Expiry>('week')
  const [limit, setLimit] = useState<UseLimit>('one')
  const [uses, setUses] = useState('5')
  const usesNumber = Number(uses)
  const usesValid = limit !== 'number' || (Number.isInteger(usesNumber) && usesNumber >= 1 && usesNumber <= MAX_USES)
  const noteValid = note.trim().length <= 200

  const submit = () => {
    if (!usesValid || !noteValid) return
    create.mutate(
      {
        note: note.trim(),
        expiresAt: expiry === 'never' ? null : new Date(Date.now() + EXPIRY_MS[expiry]).toISOString(),
        maxUses: limit === 'one' ? 1 : limit === 'number' ? usesNumber : null,
      },
      { onSuccess: onMade },
    )
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !create.isPending && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('admin.codes.newTitle')}</DialogTitle>
          <DialogDescription>{t('admin.codes.newDescription')}</DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          noValidate
          onSubmit={(e) => {
            e.preventDefault()
            submit()
          }}
        >
          <Field label={t('admin.codes.note')} description={t('admin.codes.noteHint')} error={noteValid ? undefined : t('admin.codes.noteTooLong')}>
            {(field) => <Input {...field} value={note} onChange={(e) => setNote(e.target.value)} maxLength={200} autoFocus />}
          </Field>
          <Field label={t('admin.codes.expires')}>
            {() => <Choice value={expiry} options={EXPIRIES} labelPrefix="admin.codes.expiry" onChange={setExpiry} ariaLabel={t('admin.codes.expires')} />}
          </Field>
          <Field label={t('admin.codes.usesLabel')} description={t('admin.codes.usesHint')}>
            {() => <Choice value={limit} options={USE_LIMITS} labelPrefix="admin.codes.limit" onChange={setLimit} ariaLabel={t('admin.codes.usesLabel')} />}
          </Field>
          {limit === 'number' ? (
            <Field label={t('admin.codes.howMany')} error={usesValid ? undefined : t('admin.codes.howManyRange', { max: MAX_USES })} required>
              {(field) => (
                <Input {...field} value={uses} onChange={(e) => setUses(e.target.value)} type="number" min={1} max={MAX_USES} step={1} inputMode="numeric" />
              )}
            </Field>
          ) : null}
          {create.isError ? <Alert variant="error">{apiErrorMessage(create.error, t('admin.codes.createFailed'))}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={create.isPending}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={create.isPending} disabled={!usesValid || !noteValid}>
              {t('admin.codes.make')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** The code just made: shown here once, with ways to pass it on. */
function MadeCodeDialog({ code, onClose }: { code: CreatedRegistrationCode; onClose: () => void }) {
  const { t } = useTranslation()
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('admin.codes.madeTitle')}</DialogTitle>
          <DialogDescription>{t('admin.codes.madeDescription')}</DialogDescription>
        </DialogHeader>
        <p className="rounded-md border border-border bg-muted px-4 py-3 text-center font-mono text-lg tracking-wider" aria-label={t('admin.codes.theCode')}>
          {code.code}
        </p>
        <div className="flex flex-wrap justify-center gap-2">
          <Button variant="outline" onClick={() => void copyText(code.code).then(() => toast.success(t('common.copied')))}>
            <Copy aria-hidden />
            {t('admin.codes.copyCode')}
          </Button>
          <Button variant="outline" onClick={() => void copyText(signUpLink(code.code)).then(() => toast.success(t('common.copied')))}>
            <Link2 aria-hidden />
            {t('admin.codes.copyLink')}
          </Button>
        </div>
        <DialogFooter>
          <Button onClick={onClose}>{t('admin.codes.done')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function UsesDialog({ code, onClose }: { code: RegistrationCode; onClose: () => void }) {
  const { t, i18n } = useTranslation()
  const uses = useRegistrationCodeUses(code.id)
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('admin.codes.usesTitle', { hint: code.hint })}</DialogTitle>
          <DialogDescription>{code.note || t('admin.codes.noNote')}</DialogDescription>
        </DialogHeader>
        {uses.isPending ? <LoadingPanel label={t('common.loading')} /> : null}
        {uses.isError ? <Alert variant="error">{apiErrorMessage(uses.error, t('common.tryAgain'))}</Alert> : null}
        {uses.data ? (
          <ul className="divide-y divide-border">
            {uses.data.map((use) => (
              <li key={use.userId} className="flex items-center justify-between py-2 text-sm">
                <a className="font-medium text-primary hover:underline" href={`/admin/users/${use.userId}`}>
                  {use.username}
                </a>
                <span className="text-muted-foreground">{formatInstant(use.usedAt, i18n.language)}</span>
              </li>
            ))}
          </ul>
        ) : null}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t('common.close')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
