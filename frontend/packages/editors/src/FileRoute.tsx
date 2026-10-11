import { lazy, Suspense } from 'react'
import { useTranslation } from 'react-i18next'
import { LoadingPanel } from '@kutup/ui/components/states'

// The file page and its editors load when a file is opened, not with the
// app's home: Drive and Office route here.
const FileEditorPage = lazy(() => import('./FileEditorPage').then((m) => ({ default: m.FileEditorPage })))

/** `/file/:cid/:fid`, and `/shared/file/:fid` (`shared`): one file, full screen. */
export function FileRoute({ shared = false }: { shared?: boolean }) {
  const { t } = useTranslation()
  return (
    <Suspense
      fallback={
        <div className="flex min-h-svh items-center justify-center bg-background">
          <LoadingPanel label={t('file.opening')} />
        </div>
      }
    >
      <FileEditorPage shared={shared} />
    </Suspense>
  )
}
