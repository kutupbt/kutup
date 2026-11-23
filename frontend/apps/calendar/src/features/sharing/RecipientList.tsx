import { useTranslation } from 'react-i18next'
import { Alert } from '@kutup/ui/components/alert'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { trusted, type KeyRecipient } from './client'

/**
 * Who gets a calendar's next key, each as the pins see them (verified, as
 * before, first time, changed…): an account the server slipped in shows.
 */
export function RecipientList({ recipients, pending, error }: { recipients: KeyRecipient[] | undefined; pending: boolean; error: unknown }) {
  const { t } = useTranslation()
  return (
    <section className="space-y-1.5" aria-labelledby="key-recipients-title">
      <h4 id="key-recipients-title" className="text-sm font-medium">
        {t('sharing.recipients.title')}
      </h4>
      {pending ? (
        <p className="text-sm text-muted-foreground">{t('common.loading')}</p>
      ) : error ? (
        <Alert variant="error">{apiErrorMessage(error, t('sharing.errors.loadFailed'))}</Alert>
      ) : recipients?.length ? (
        <ul className="divide-y divide-border rounded-md border border-border text-sm" data-testid="key-recipients">
          {recipients.map((person) => (
            <li key={person.accountId} className="flex flex-wrap items-center gap-2 px-3 py-1.5" data-testid="key-recipient">
              <span className="min-w-0 flex-1 truncate">{person.address}</span>
              <span className={trusted(person) ? 'text-xs text-muted-foreground' : 'text-xs text-destructive'}>{t(`sharing.recipients.state.${person.state}`)}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-muted-foreground">{t('sharing.recipients.onlyYou')}</p>
      )}
    </section>
  )
}
