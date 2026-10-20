import { Plus, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { FilterCondition, FilterField, FilterOp } from '@kutup/mail-core/filters'
import { emptyCondition, type Conditions } from './conditions'
import { Button } from '@kutup/ui/components/button'
import { Input } from '@kutup/ui/components/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'

const OPS: FilterOp[] = ['contains', 'is', 'begins', 'ends', 'matches']

/** At most this many conditions (the server's limit). */
const MAX_CONDITIONS = 20

/**
 * Proton's filter conditions: on the subject, sender, recipient or
 * attachments with contains, is exactly, begins with, ends with or matches
 * (and their negations), all or any. Filters use every field; forwarding
 * leaves the recipient out, and may have no condition at all (everything is
 * forwarded).
 */
export function ConditionsEditor({
  value,
  onChange,
  fields,
  allowNone = false,
  error,
}: {
  value: Conditions
  onChange: (value: Conditions) => void
  fields: FilterField[]
  /** No condition is allowed (it means every message). */
  allowNone?: boolean
  error?: string
}) {
  const { t } = useTranslation()
  const setCondition = (i: number, change: Partial<FilterCondition>) =>
    onChange({ ...value, conditions: value.conditions.map((c, n) => (n === i ? { ...c, ...change } : c)) })
  const opValue = (c: FilterCondition) => `${c.negate ? 'not-' : ''}${c.op}`

  return (
    <div className="space-y-3">
      <div role="radiogroup" aria-label={t('filters.match')} className="flex flex-wrap gap-4 text-sm">
        {(['all', 'any'] as const).map((m) => (
          <label key={m} className="flex items-center gap-2">
            <input type="radio" name="match" checked={value.match === m} onChange={() => onChange({ ...value, match: m })} />
            {t(`filters.match_${m}`)}
          </label>
        ))}
      </div>
      <ul className="space-y-2">
        {value.conditions.map((c, i) => (
          <li key={i} className="flex flex-wrap items-center gap-2 rounded-md border border-border p-2">
            <Select value={c.field} onValueChange={(field) => setCondition(i, { field: field as FilterField })}>
              <SelectTrigger className="w-40" aria-label={t('filters.field')}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {fields.map((f) => (
                  <SelectItem key={f} value={f}>
                    {t(`filters.fields.${f}`)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {c.field === 'attachments' ? (
              <Select value={c.negate ? 'none' : 'has'} onValueChange={(v) => setCondition(i, { negate: v === 'none' })}>
                <SelectTrigger className="w-48" aria-label={t('filters.comparator')}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="has">{t('filters.hasAttachments')}</SelectItem>
                  <SelectItem value="none">{t('filters.noAttachments')}</SelectItem>
                </SelectContent>
              </Select>
            ) : (
              <>
                <Select
                  value={opValue(c)}
                  onValueChange={(v) => setCondition(i, { negate: v.startsWith('not-'), op: v.replace(/^not-/, '') as FilterOp })}
                >
                  <SelectTrigger className="w-44" aria-label={t('filters.comparator')}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {OPS.map((op) => (
                      <SelectItem key={op} value={op}>
                        {t(`filters.ops.${op}`)}
                      </SelectItem>
                    ))}
                    {OPS.map((op) => (
                      <SelectItem key={`not-${op}`} value={`not-${op}`}>
                        {t(`filters.notOps.${op}`)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Input
                  className="min-w-40 flex-1"
                  aria-label={t('filters.value')}
                  placeholder={c.op === 'matches' ? t('filters.matchesHint') : t('filters.valuePlaceholder')}
                  maxLength={200}
                  value={c.value}
                  onChange={(e) => setCondition(i, { value: e.target.value })}
                />
              </>
            )}
            <Button
              variant="ghost"
              size="icon"
              className="size-8"
              aria-label={t('filters.removeCondition')}
              disabled={!allowNone && value.conditions.length === 1}
              onClick={() => onChange({ ...value, conditions: value.conditions.filter((_, n) => n !== i) })}
            >
              <Trash2 />
            </Button>
          </li>
        ))}
      </ul>
      <Button
        variant="outline"
        size="sm"
        disabled={value.conditions.length >= MAX_CONDITIONS}
        onClick={() => onChange({ ...value, conditions: [...value.conditions, emptyCondition(fields[0])] })}
      >
        <Plus />
        {t('filters.addCondition')}
      </Button>
      {error ? <p className="text-sm text-destructive">{error}</p> : null}
    </div>
  )
}
