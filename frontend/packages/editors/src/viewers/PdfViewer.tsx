import type { ViewerProps } from './dispatch'

export default function PdfViewer({ filename, blobUrl }: ViewerProps) {
  // Native browser PDF rendering. The blob: URL is opaque to the embedder so
  // there's no cross-origin restriction; print/download buttons in the viewer
  // chrome operate on the local Blob.
  return (
    <div className="h-full w-full bg-background">
      <iframe
        src={blobUrl}
        title={filename}
        className="h-full w-full border-0"
      />
    </div>
  )
}
