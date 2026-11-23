import { Download } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Label } from '@kutup/ui/components/label'
import type { GeneratedKeyFile } from './useGeneratedKeyFile'

/** The generate button and the "I saved it" confirmation. */
export function GeneratedKeyFileField({ keyFile, id, onGenerate }: { keyFile: GeneratedKeyFile; id: string; onGenerate: () => void }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-2">
      <Button type="button" variant="outline" size="sm" onClick={onGenerate} data-testid={`${id}-generate`}>
        <Download />
        {keyFile.name ? t('changeKey.downloadAgain') : t('changeKey.generateKeyFile')}
      </Button>
      {keyFile.name ? (
        <div className="flex items-start gap-2">
          <Checkbox id={`${id}-saved`} checked={keyFile.saved} onCheckedChange={(v) => keyFile.setSaved(v === true)} />
          <Label htmlFor={`${id}-saved`} className="text-sm font-normal">
            {t('changeKey.keyFileSaved', { name: keyFile.name })}
          </Label>
        </div>
      ) : null}
    </div>
  )
}
