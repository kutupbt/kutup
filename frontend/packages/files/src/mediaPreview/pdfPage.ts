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
export async function renderPdfFirstPageV1(
  bytes: ArrayBuffer,
  maxEdge: number,
  signal?: AbortSignal,
  options: { trim?: boolean } = {},
): Promise<Blob | null> {
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
    const out = options.trim ? trimmed(canvas, context) : canvas
    return await new Promise<Blob | null>((resolve) => out.toBlob(resolve, 'image/png'))
  } catch {
    return null
  } finally {
    signal?.removeEventListener('abort', abort)
    void task.destroy()
  }
}

/** Near-white counts as paper. */
const PAPER_THRESHOLD = 245

/**
 * The page cropped to what is drawn on it, with a margin — for spreadsheets,
 * whose few used cells would otherwise be a speck on an empty sheet. A blank
 * page is returned whole.
 */
function trimmed(canvas: HTMLCanvasElement, context: CanvasRenderingContext2D): HTMLCanvasElement {
  const box = contentBox(context.getImageData(0, 0, canvas.width, canvas.height))
  if (!box) return canvas
  const margin = Math.round(Math.max(canvas.width, canvas.height) * 0.02)
  // At least a quarter of the page wide, so a single cell is not blown up.
  let width = Math.max(Math.round(canvas.width / 4), box.right - box.left + 1 + margin * 2)
  let height = box.bottom - box.top + 1 + margin * 2
  // The shape of a grid card (4:3), so the card never cuts the content off:
  // grow the short side, into the page where there is page, else paper.
  if (width / height > CARD_RATIO) height = Math.round(width / CARD_RATIO)
  else width = Math.round(height * CARD_RATIO)
  const left = Math.max(0, box.left - margin)
  const top = Math.max(0, box.top - margin)
  const out = globalThis.document.createElement('canvas')
  out.width = width
  out.height = height
  const outContext = out.getContext('2d', { alpha: false })
  if (!outContext) return canvas
  outContext.fillStyle = '#ffffff'
  outContext.fillRect(0, 0, width, height)
  const sw = Math.min(width, canvas.width - left)
  const sh = Math.min(height, canvas.height - top)
  outContext.drawImage(canvas, left, top, sw, sh, 0, 0, sw, sh)
  return out
}

/** Grid cards are 4:3. */
const CARD_RATIO = 4 / 3

/** The smallest box around every non-paper pixel, or null for a blank page. */
export function contentBox(image: { width: number; height: number; data: Uint8ClampedArray }):
  { left: number; top: number; right: number; bottom: number } | null {
  const { width, height, data } = image
  let left = width
  let top = height
  let right = -1
  let bottom = -1
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const i = (y * width + x) * 4
      if (data[i]! < PAPER_THRESHOLD || data[i + 1]! < PAPER_THRESHOLD || data[i + 2]! < PAPER_THRESHOLD) {
        if (x < left) left = x
        if (x > right) right = x
        if (y < top) top = y
        if (y > bottom) bottom = y
      }
    }
  }
  return right < 0 ? null : { left, top, right, bottom }
}
