import type { FilterCondition, FilterField } from '@kutup/mail-core/filters'

/** A filter's or a forwarding's conditions, and how they combine. */
export interface Conditions {
  match: 'all' | 'any'
  conditions: FilterCondition[]
}

export function emptyCondition(field: FilterField = 'subject'): FilterCondition {
  return { field, op: 'contains', negate: false, value: '' }
}
