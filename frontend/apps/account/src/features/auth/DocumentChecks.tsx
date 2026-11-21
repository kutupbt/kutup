import { ExternalLink } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { documentName, type LegalDocument } from './legal'

/**
 * A checkbox per document to confirm, each with a link to its text
 * (docs/plans/server-personal-data.md, A3). `checked`: the ids confirmed.
 */
export function DocumentChecks({
  documents,
  checked,
  onChange,
  error,
}: {
  documents: LegalDocument[]
  checked: string[]
  onChange: (checked: string[]) => void
  error?: string | null
}) {
  const { t } = useTranslation()
  if (documents.length === 0) return null
  return (
    <fieldset className="space-y-2">
      {documents.map((document) => (
        <label key={document.id} className="flex items-start gap-2 text-sm">
          <Checkbox
            className="mt-0.5"
            checked={checked.includes(document.id)}
            onCheckedChange={(value) =>
              onChange(value === true ? [...checked, document.id] : checked.filter((id) => id !== document.id))
            }
          />
          <span>
            {t('legal.confirm', { name: documentName(t, document.kind), version: document.version })}{' '}
            <a
              href={document.url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 font-medium text-primary underline-offset-4 hover:underline"
            >
              {t('legal.read')} <ExternalLink className="size-3" />
            </a>
          </span>
        </label>
      ))}
      {error ? <p className="text-sm text-destructive">{error}</p> : null}
    </fieldset>
  )
}
