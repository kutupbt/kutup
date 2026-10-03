import { Upload } from 'lucide-react'
import { useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { useLibraryContext } from '../library/libraryContext'

/** Pick photos and videos to upload into the upload folder. */
export function UploadButton() {
  const { t } = useTranslation()
  const { upload, preferences } = useLibraryContext()
  const input = useRef<HTMLInputElement>(null)
  return (
    <>
      <Button className="w-full justify-start" disabled={!preferences} onClick={() => input.current?.click()}>
        <Upload /> {t('upload.button')}
      </Button>
      <input
        ref={input}
        type="file"
        multiple
        accept="image/*,video/*,.heic,.heif,.dng,.cr2,.cr3,.nef,.arw,.raf,.orf,.rw2"
        className="sr-only"
        tabIndex={-1}
        aria-hidden
        onChange={(e) => {
          const files = [...(e.target.files ?? [])]
          e.target.value = ''
          if (files.length) void upload(files)
        }}
      />
    </>
  )
}
