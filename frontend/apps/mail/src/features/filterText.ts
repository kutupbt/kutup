import type { TFunction } from 'i18next'
import type { FilterDraft } from '@kutup/mail-core/filters'
import { folderPath, type MailPlaces } from '@kutup/mail-core/places'

/** A filter in one sentence, for its preview and the filter list. */
export function describeFilter(draft: Pick<FilterDraft, 'match' | 'conditions' | 'actions'>, places: MailPlaces | undefined, t: TFunction): string {
  const conditions = draft.conditions.map((c) =>
    c.field === 'attachments'
      ? t(c.negate ? 'filters.text.noAttachments' : 'filters.text.hasAttachments')
      : t('filters.text.condition', {
          field: t(`filters.text.fields.${c.field}`),
          op: t(c.negate ? `filters.notOps.${c.op}` : `filters.ops.${c.op}`),
          value: c.value.trim(),
        }),
  )
  const actions: string[] = []
  const folder = draft.actions.folder
  if (folder) {
    const name = folder.startsWith('custom:') ? (places ? folderPath(places, folder.slice(7)) || '…' : '…') : t(`folders.${folder}`)
    actions.push(t('filters.text.move', { name }))
  }
  const labels = (draft.actions.labels ?? []).map((id) => places?.labelsById.get(id)?.name ?? '…')
  if (labels.length) actions.push(t('filters.text.label', { names: labels.join(', ') }))
  if (draft.actions.markRead) actions.push(t('filters.text.markRead'))
  if (draft.actions.star) actions.push(t('filters.text.star'))
  return t(draft.match === 'any' ? 'filters.text.any' : 'filters.text.all', {
    conditions: conditions.join(t('filters.text.joiner')),
    actions: actions.join(', '),
  })
}
