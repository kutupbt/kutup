import { ImageOff } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { ViewerProps } from './dispatch'

export default function ImageViewer({ filename, blobUrl }: ViewerProps) {
  const { t } = useTranslation()
  // A file named .jpg that is not one (or a format this browser lacks, like HEIC).
  const [broken, setBroken] = useState(false)
  if (broken) {
    return (
      <div className="flex h-full w-full flex-col items-center justify-center gap-3 p-6 text-center text-sm text-muted-foreground">
        <ImageOff className="size-10" aria-hidden />
        {t('viewer.imageUnreadable')}
      </div>
    )
  }
  return (
    <div className="flex h-full w-full items-center justify-center overflow-auto bg-muted/40 p-4">
      <img
        src={blobUrl}
        alt={filename}
        onError={() => setBroken(true)}
        className="max-h-full max-w-full object-contain"
        draggable={false}
      />
    </div>
  )
}
