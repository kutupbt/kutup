import { useId, type ReactNode } from 'react'
import { cn } from '../lib/cn'
import { Label } from './label'

/** Props a `Field` hands to its control so labelling and errors are wired. */
export interface FieldControlProps {
  id: string
  'aria-invalid': boolean
  'aria-describedby': string | undefined
}

/**
 * Label + control + error, with the accessibility wiring done once.
 *
 * The control is a render prop rather than a context consumer: the props it
 * needs are explicit and type-checked, so a field cannot silently lose its
 * `aria-describedby` the way a context-based version can when someone nests a
 * wrapper in between.
 */
export function Field({
  label,
  error,
  description,
  required,
  className,
  children,
}: {
  label: string
  error?: string
  description?: string
  required?: boolean
  className?: string
  children: (props: FieldControlProps) => ReactNode
}) {
  const id = useId()
  const errorId = `${id}-error`
  const descriptionId = `${id}-description`

  const describedBy =
    [error ? errorId : null, description ? descriptionId : null].filter(Boolean).join(' ') ||
    undefined

  return (
    <div className={cn('space-y-1.5', className)}>
      {/*
        The required marker is a *sibling* of the label, not a child of it.
        Inside, it becomes part of the label's text: the accessible name is
        computed with `aria-hidden` stripped and so reads "Severity", but
        anything matching on the label's raw text — Playwright's `getByLabel`,
        among others — sees "Severity*" and an anchored or exact match finds
        nothing. Two different answers to "what is this field called" is one
        too many, and the visible name is the one that was wrong.
      */}
      <div className="flex items-center gap-0.5">
        <Label htmlFor={id}>{label}</Label>
        {required ? (
          <span className="text-destructive" aria-hidden>
            *
          </span>
        ) : null}
      </div>

      {children({ id, 'aria-invalid': Boolean(error), 'aria-describedby': describedBy })}

      {description ? (
        <p id={descriptionId} className="text-xs text-muted-foreground">
          {description}
        </p>
      ) : null}

      {error ? (
        <p id={errorId} role="alert" className="text-xs font-medium text-destructive">
          {error}
        </p>
      ) : null}
    </div>
  )
}
