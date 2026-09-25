import type { ReactNode } from 'react'
import { Checkbox } from '@kutup/ui/components/checkbox'

/** One on/off setting: a checkbox with its title and explanation. */
export function Toggle({
  checked,
  onChange,
  title,
  description,
  testId,
  disabled,
}: {
  checked: boolean
  onChange: (value: boolean) => void
  title: string
  description: ReactNode
  testId: string
  disabled?: boolean
}) {
  return (
    <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-border p-4">
      <Checkbox checked={checked} disabled={disabled} onCheckedChange={(value) => onChange(value === true)} className="mt-0.5" data-testid={testId} />
      <span>
        <span className="block text-sm font-medium">{title}</span>
        <span className="mt-1 block text-sm text-muted-foreground">{description}</span>
      </span>
    </label>
  )
}
