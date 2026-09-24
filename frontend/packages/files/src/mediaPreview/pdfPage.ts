// The first page of a PDF as a picture (Drive thumbnails). PDF.js is pinned
// (package.json) and loaded only when a PDF needs drawing; it parses in its
// own worker. Nothing active runs: no scripting (the sandbox build is never
// loaded), no XFA forms, no fetching of anything outside the bytes given.

/** Refuse PDFs larger than this outright (the whole file is parsed in memory). */
export const MAX_PDF_BYTES = 64 * 1024 * 1024
/** Any single image inside the page may not exceed this many pixels. */
const MAX_IMAGE_PIXELS = 16_000_000

/**
 * Page one, rendered so its longest side is `maxEdge` px, as PNG; null when
 * the bytes are not a PDF this can draw (encrypted, damaged, too large).
 */
export async function renderPdfFirstPageV1(bytes: ArrayBuffer, maxEdge: number, signal?: AbortSignal): Promise<Blob | null> {
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_PDF_BYTES) return null
  const pdfjs = await import('pdfjs-dist')
  pdfjs.GlobalWorkerOptions.workerSrc = new URL('pdfjs-dist/build/pdf.worker.min.mjs', import.meta.url).href
  const task = pdfjs.getDocument({
    data: new Uint8Array(bytes),
    enableXfa: false,
    disableRange: true,
    disableStream: true,
    disableAutoFetch: true,
    maxImageSize: MAX_IMAGE_PIXELS,
    stopAtErrors: false,
  })
  const abort = () => void task.destroy()
  signal?.addEventListener('abort', abort, { once: true })
  try {
    const document = await task.promise
    const page = await document.getPage(1)
    const unscaled = page.getViewport({ scale: 1 })
    const scale = maxEdge / Math.max(unscaled.width, unscaled.height)
    const viewport = page.getViewport({ scale })
    const canvas = globalThis.document.createElement('canvas')
    canvas.width = Math.max(1, Math.floor(viewport.width))
    canvas.height = Math.max(1, Math.floor(viewport.height))
    const context = canvas.getContext('2d', { alpha: false })
    if (!context) return null
    // Paper, then the page on it (a page without a background is transparent).
    context.fillStyle = '#ffffff'
    context.fillRect(0, 0, canvas.width, canvas.height)
    await page.render({ canvas, canvasContext: context, viewport, annotationMode: pdfjs.AnnotationMode.ENABLE }).promise
    return await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, 'image/png'))
  } catch {
    return null
  } finally {
    signal?.removeEventListener('abort', abort)
    void task.destroy()
  }
}
