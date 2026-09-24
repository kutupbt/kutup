import { classifyFileForKutup } from './fileSafety'
import { inspectRasterDimensions } from './imageDimensions'
import { layoutTextPage } from './textPage'
import type {
  PreviewWorkerRequestV1,
  RasterOutputType,
  RasterPreviewWorkerResponseV1,
} from './workerProtocol'

const QUALITY_STEPS = [0.82, 0.68, 0.52, 0.38]
const MIN_EDGE = 64

self.onmessage = async (event: MessageEvent<PreviewWorkerRequestV1>) => {
  if (event.origin !== '' && event.origin !== self.location.origin) {
    post({ type: 'error', message: 'Unauthorized origin' })
    return
  }
  try {
    const request = event.data
    if (request.type !== 'raster-image-v1' && request.type !== 'text-page-v1') {
      throw new Error('unknown preview worker request')
    }
    if (!Number.isSafeInteger(request.maxEdge) || request.maxEdge < 1 ||
        !Number.isSafeInteger(request.maxOutputBytes) || request.maxOutputBytes < 1) {
      throw new Error('invalid preview worker limits')
    }
    const outputTypes = checkOutputTypes(request.outputTypes)
    if (typeof OffscreenCanvas === 'undefined') throw new Error('bounded raster worker is unavailable')
    if (request.type === 'text-page-v1') {
      await drawTextPage(request.text, request.mode, request.maxEdge, request.maxOutputBytes, outputTypes)
      return
    }
    if (!Number.isSafeInteger(request.maxInputPixels) || request.maxInputPixels < 1) {
      throw new Error('invalid preview worker limits')
    }
    if (typeof createImageBitmap !== 'function') throw new Error('bounded raster worker is unavailable')
    const bytes = new Uint8Array(request.bytes)
    const safety = classifyFileForKutup({
      filename: request.filename,
      mimeType: request.mimeType,
      bytes: bytes.subarray(0, Math.min(bytes.length, 4096)),
    })
    if (safety.classification !== 'previewable' || !safety.detectedMimeType?.startsWith('image/')) {
      throw new Error('image failed preview safety classification')
    }
    const dimensions = inspectRasterDimensions(bytes, safety.detectedMimeType)
    if (!dimensions || dimensions.width * dimensions.height > request.maxInputPixels) {
      throw new Error('image dimensions exceed preview budget')
    }
    const bitmap = await createImageBitmap(new Blob([bytes], { type: safety.detectedMimeType }), {
      imageOrientation: 'from-image',
    })
    try {
      if (bitmap.width !== dimensions.width || bitmap.height !== dimensions.height ||
          bitmap.width * bitmap.height > request.maxInputPixels) {
        throw new Error('decoded image dimensions differ from bounded header')
      }
      const initialScale = Math.min(1, request.maxEdge / Math.max(bitmap.width, bitmap.height))
      let width = Math.max(1, Math.round(bitmap.width * initialScale))
      let height = Math.max(1, Math.round(bitmap.height * initialScale))
      for (;;) {
        const canvas = new OffscreenCanvas(width, height)
        const context = canvas.getContext('2d', { alpha: false })
        if (!context) throw new Error('preview canvas is unavailable')
        context.drawImage(bitmap, 0, 0, width, height)
        const encoded = await encode(canvas, request.maxOutputBytes, outputTypes)
        if (encoded) {
          post({
            type: 'raster-image-result-v1',
            raster: encoded.raster,
            contentType: encoded.contentType,
            width,
            height,
            sourceWidth: bitmap.width,
            sourceHeight: bitmap.height,
          }, [encoded.raster])
          return
        }
        if (Math.max(width, height) <= MIN_EDGE) break
        width = Math.max(1, Math.round(width * 0.75))
        height = Math.max(1, Math.round(height * 0.75))
      }
      throw new Error('image could not fit the preview byte budget')
    } finally {
      bitmap.close()
    }
  } catch (error) {
    post({ type: 'error', message: error instanceof Error ? error.message : 'preview generation failed' })
  }
}

function checkOutputTypes(value: RasterOutputType[] | undefined): RasterOutputType[] {
  const types = value ?? ['image/webp']
  if (types.length === 0 || types.some((t) => t !== 'image/webp' && t !== 'image/jpeg')) {
    throw new Error('invalid preview output types')
  }
  return types
}

/**
 * The first requested encoding this browser really produces (Safari's
 * canvas cannot encode WebP and quietly returns PNG), at the best quality
 * that fits the byte budget; null when none fits at this size.
 */
async function encode(
  canvas: OffscreenCanvas,
  maxOutputBytes: number,
  outputTypes: RasterOutputType[],
): Promise<{ raster: ArrayBuffer; contentType: RasterOutputType } | null> {
  for (const type of outputTypes) {
    for (const quality of QUALITY_STEPS) {
      const blob = await canvas.convertToBlob({ type, quality })
      if (blob.type !== type) break
      if (blob.size > 0 && blob.size <= maxOutputBytes) {
        return { raster: await blob.arrayBuffer(), contentType: type }
      }
    }
  }
  return null
}

const PAPER = '#ffffff'
const INK = '#1f2937'
const RULE = '#e5e7eb'

async function drawTextPage(
  text: string,
  mode: 'prose' | 'code',
  maxEdge: number,
  maxOutputBytes: number,
  outputTypes: RasterOutputType[],
): Promise<void> {
  // A portrait page, 3:4, whose longest side is the budget's.
  const height = maxEdge
  const width = Math.round((maxEdge * 3) / 4)
  const page = layoutTextPage(text, mode, width, height)
  const canvas = new OffscreenCanvas(width, height)
  const context = canvas.getContext('2d', { alpha: false })
  if (!context) throw new Error('preview canvas is unavailable')
  context.fillStyle = PAPER
  context.fillRect(0, 0, width, height)
  context.textBaseline = 'top'
  for (const line of page.lines) {
    if (line.rule) {
      context.fillStyle = RULE
      context.fillRect(page.margin, line.y, width - page.margin * 2, Math.max(1, Math.round(line.size / 12)))
      continue
    }
    context.fillStyle = INK
    context.font = `${line.bold ? '600 ' : ''}${line.size}px ${mode === 'code' ? 'ui-monospace, monospace' : 'system-ui, sans-serif'}`
    context.fillText(line.text, page.margin, line.y)
  }
  const encoded = await encode(canvas, maxOutputBytes, outputTypes)
  if (!encoded) throw new Error('text page could not fit the preview byte budget')
  post({
    type: 'raster-image-result-v1',
    raster: encoded.raster,
    contentType: encoded.contentType,
    width,
    height,
    sourceWidth: width,
    sourceHeight: height,
  }, [encoded.raster])
}

function post(message: RasterPreviewWorkerResponseV1, transfer: Transferable[] = []): void {
  self.postMessage(message, { transfer })
}
