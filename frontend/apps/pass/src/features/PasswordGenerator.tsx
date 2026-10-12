import { RefreshCw, Wand2 } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Label } from '@kutup/ui/components/label'
import { Popover, PopoverContent, PopoverTrigger } from '@kutup/ui/components/popover'
import { DEFAULT_OPTIONS, entropyBits, generatePassword, type GeneratorOptions } from '../lib/generator'

/** Makes a random password and hands it to the field. */
export function PasswordGenerator({ onUse }: { onUse: (password: string) => void }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [options, setOptions] = useState<GeneratorOptions>(DEFAULT_OPTIONS)
  const [candidate, setCandidate] = useState(() => generatePassword(DEFAULT_OPTIONS))
  const update = (next: GeneratorOptions) => {
    if (!next.lower && !next.upper && !next.digits && !next.symbols) return
    setOptions(next)
    setCandidate(generatePassword(next))
  }
  const toggles: (keyof Pick<GeneratorOptions, 'lower' | 'upper' | 'digits' | 'symbols' | 'avoidLookAlikes'>)[] = [
    'lower',
    'upper',
    'digits',
    'symbols',
    'avoidLookAlikes',
  ]
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button type="button" variant="outline" size="icon" aria-label={t('generator.open')}>
          <Wand2 />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-80 space-y-4" align="end">
        <div className="flex items-center gap-2">
          <code className="min-w-0 flex-1 break-all rounded bg-muted px-2 py-1.5 font-mono text-sm" aria-live="polite">
            {candidate}
          </code>
          <Button type="button" variant="ghost" size="icon" onClick={() => setCandidate(generatePassword(options))} aria-label={t('generator.again')}>
            <RefreshCw />
          </Button>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="generator-length">{t('generator.length', { count: options.length })}</Label>
          <input
            id="generator-length"
            type="range"
            min={8}
            max={64}
            value={options.length}
            onChange={(e) => update({ ...options, length: Number(e.target.value) })}
            className="w-full accent-primary"
          />
        </div>
        <div className="grid grid-cols-2 gap-2">
          {toggles.map((name) => (
            <div key={name} className="flex items-center gap-2">
              <Checkbox id={`generator-${name}`} checked={options[name]} onCheckedChange={(v) => update({ ...options, [name]: v === true })} />
              <Label htmlFor={`generator-${name}`} className="text-sm font-normal">
                {t(`generator.${name}`)}
              </Label>
            </div>
          ))}
        </div>
        <p className="text-xs text-muted-foreground">{t('generator.bits', { bits: entropyBits(options) })}</p>
        <Button
          type="button"
          className="w-full"
          onClick={() => {
            onUse(candidate)
            setOpen(false)
          }}
        >
          {t('generator.use')}
        </Button>
      </PopoverContent>
    </Popover>
  )
}
