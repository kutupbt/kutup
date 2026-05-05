import type { ViewerProps } from './dispatch'

export default function ImageViewer({ filename, blobUrl }: ViewerProps) {
  return (
    <div className="flex h-full w-full items-center justify-center overflow-auto bg-muted/40 p-4">
      <img
        src={blobUrl}
        alt={filename}
        className="max-h-full max-w-full object-contain"
        draggable={false}
      />
    </div>
  )
}
