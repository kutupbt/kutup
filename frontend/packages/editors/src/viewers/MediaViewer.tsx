import type { ViewerProps } from './dispatch'

export default function MediaViewer({ filename, blobUrl, mimeType }: ViewerProps) {
  const isVideo = mimeType.startsWith('video/')

  return (
    <div className="flex h-full w-full items-center justify-center bg-muted/40 p-4">
      {isVideo ? (
        <video
          src={blobUrl}
          title={filename}
          controls
          className="max-h-full max-w-full"
        />
      ) : (
        <audio
          src={blobUrl}
          title={filename}
          controls
          className="w-full max-w-md"
        />
      )}
    </div>
  )
}
