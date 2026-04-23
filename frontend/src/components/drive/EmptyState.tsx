import { Upload } from 'lucide-react'
import { useTranslation } from 'react-i18next'

interface Props {
  canUpload: boolean
  onClick: () => void
}

export default function EmptyState({ canUpload, onClick }: Props) {
  const { t } = useTranslation()
  return (
    <div
      className="border-2 border-dashed border-border rounded-xl p-16 text-center mt-6 cursor-pointer hover:border-primary/50 transition-colors"
      onClick={canUpload ? onClick : undefined}
    >
      <Upload className="h-10 w-10 text-muted-foreground mx-auto mb-3 opacity-50" />
      {canUpload ? (
        <p className="text-sm text-muted-foreground">
          {t('upload.dropOrClick')}{' '}
          <span className="text-primary cursor-pointer hover:underline">{t('upload.clickToUpload')}</span>
        </p>
      ) : (
        <p className="text-sm text-muted-foreground">{t('upload.readOnly')}</p>
      )}
    </div>
  )
}
