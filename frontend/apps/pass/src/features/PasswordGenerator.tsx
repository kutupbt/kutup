import { Wand2 } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { Popover, PopoverContent, PopoverTrigger } from '@kutup/ui/components/popover'
import { GeneratorPanel } from './GeneratorPanel'

/** Makes a random password or passphrase and hands it to the field. */
export function PasswordGenerator({ onUse }: { onUse: (password: string) => void }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button type="button" variant="outline" size="icon" aria-label={t('generator.open')}>
          <Wand2 />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-96 max-w-[calc(100vw-2rem)]" align="end">
        {open ? (
          <GeneratorPanel
            onUse={(value) => {
              onUse(value)
              setOpen(false)
            }}
          />
        ) : null}
      </PopoverContent>
    </Popover>
  )
}
