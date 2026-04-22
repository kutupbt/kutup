import { Progress } from '@/components/ui/progress'
import { formatSpeed } from '@/lib/format'
import type { UploadState } from '@/types/drive'

interface Props {
  state: UploadState
}

export default function UploadPanel({ state }: Props) {
  if (!state.active) return null

  return (
    <div className="fixed bottom-24 right-8 w-60 bg-card border border-border rounded-xl p-3 shadow-2xl z-50">
      <p className="text-xs text-muted-foreground mb-2">
        Uploading{' '}
        <span className="text-foreground">
          {state.currentFile} / {state.totalFiles}
        </span>
      </p>
      <Progress value={state.overallPercent} className="h-1.5 mb-2" />
      <div className="flex justify-between text-xs text-muted-foreground">
        <span>{state.overallPercent}%</span>
        <span>{formatSpeed(state.speedBps)}</span>
      </div>
    </div>
  )
}
