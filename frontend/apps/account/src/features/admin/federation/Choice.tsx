import { useTranslation } from 'react-i18next'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'

/** A Radix select over a fixed set of values, labelled through `labelPrefix.<value>`. */
export function Choice<T extends string>({
  value,
  options,
  labelPrefix,
  onChange,
  ariaLabel,
  disabled,
  className,
}: {
  value: T
  options: readonly T[]
  labelPrefix: string
  onChange: (value: T) => void
  ariaLabel: string
  disabled?: boolean
  className?: string
}) {
  const { t } = useTranslation()
  return (
    <Select value={value} onValueChange={(v) => onChange(v as T)} disabled={disabled}>
      <SelectTrigger aria-label={ariaLabel} className={className}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {options.map((option) => (
          <SelectItem key={option} value={option}>
            {t(`${labelPrefix}.${option}`)}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

export const MODES = ['disabled', 'allowlist', 'blocklist', 'open'] as const
export const TRUSTS = ['tofu', 'verified'] as const
export const RULE_ACTIONS = ['inherit', 'allow', 'block'] as const
export const RULE_TRUSTS = ['inherit', 'tofu', 'verified'] as const
export const FEATURES = ['chat', 'drive'] as const
