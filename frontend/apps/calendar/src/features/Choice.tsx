import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'

/** One of a list of options, through the design system's select. */
export function Choice({
  id,
  value,
  options,
  onChange,
  disabled,
  testId,
  label,
}: {
  id: string
  value: string
  options: readonly { value: string; label: string }[]
  onChange: (value: string) => void
  disabled?: boolean
  testId?: string
  /** Its name, where no visible label names it. */
  label?: string
}) {
  return (
    <Select value={value} onValueChange={onChange} disabled={disabled}>
      <SelectTrigger id={id} className="w-full" data-testid={testId} aria-label={label}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent className="max-h-72">
        {options.map((option) => (
          <SelectItem key={option.value} value={option.value}>
            {option.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}
