import { useTranslation } from 'react-i18next'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { GeneratorPanel } from './GeneratorPanel'

/** The generator on its own (pass.<domain>/generator), no vault needed. */
export function GeneratorPage() {
  const { t } = useTranslation()
  return (
    <PageBody width="prose">
      <PageHeader title={t('generator.title')} description={t('generator.description')} />
      <div className="max-w-md">
        <GeneratorPanel />
      </div>
    </PageBody>
  )
}
