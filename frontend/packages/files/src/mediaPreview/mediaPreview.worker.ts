import { classifyFileForKutup } from './fileSafety'
import { inspectRasterDimensions } from './imageDimensions'
import type { TokenKind } from './codeTokens'
import { layoutTextPage, type PageLine } from './textPage'
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
      const language = typeof request.language === 'string' && /^[\w+#.-]{1,32}$/.test(request.language) ? request.language : undefined
      await drawTextPage(request.text, request.mode, request.maxEdge, request.maxOutputBytes, outputTypes, language)
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
    const heif = safety.detectedMimeType === 'image/heic' || safety.detectedMimeType === 'image/heif'
    const orientation = checkOrientation(request.orientation)
    let bitmap: ImageBitmap
    let dimensions: { width: number; height: number } | null
    if (heif) {
      // No browser but Safari decodes HEIC: libheif, in this worker, with the
      // pixel budget checked before any pixels are made.
      bitmap = await decodeHeif(bytes, request.maxInputPixels)
      dimensions = { width: bitmap.width, height: bitmap.height }
    } else {
      dimensions = inspectRasterDimensions(bytes, safety.detectedMimeType)
      if (!dimensions || dimensions.width * dimensions.height > request.maxInputPixels) {
        throw new Error('image dimensions exceed preview budget')
      }
      bitmap = await createImageBitmap(new Blob([bytes], { type: safety.detectedMimeType }), {
        imageOrientation: 'from-image',
      })
    }
    try {
      if (bitmap.width !== dimensions.width || bitmap.height !== dimensions.height ||
          bitmap.width * bitmap.height > request.maxInputPixels) {
        throw new Error('decoded image dimensions differ from bounded header')
      }
      // A quarter turn swaps the sides.
      const turned = orientation >= 5
      const shownWidth = turned ? bitmap.height : bitmap.width
      const shownHeight = turned ? bitmap.width : bitmap.height
      const initialScale = Math.min(1, request.maxEdge / Math.max(shownWidth, shownHeight))
      let width = Math.max(1, Math.round(shownWidth * initialScale))
      let height = Math.max(1, Math.round(shownHeight * initialScale))
      for (;;) {
        const canvas = new OffscreenCanvas(width, height)
        const context = canvas.getContext('2d', { alpha: false })
        if (!context) throw new Error('preview canvas is unavailable')
        drawOriented(context, bitmap, width, height, orientation)
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

function checkOrientation(value: number | undefined): number {
  if (value === undefined) return 1
  if (!Number.isInteger(value) || value < 1 || value > 8) throw new Error('invalid orientation')
  return value
}

/**
 * Draw `bitmap` into a `width` × `height` canvas as EXIF orientation says it
 * is shown (1: as stored; 3: half turn; 6 and 8: quarter turns; 2, 4, 5, 7:
 * the same, mirrored).
 */
function drawOriented(context: OffscreenCanvasRenderingContext2D, bitmap: ImageBitmap, width: number, height: number, orientation: number): void {
  const turned = orientation >= 5
  const w = turned ? height : width
  const h = turned ? width : height
  switch (orientation) {
    case 2: context.setTransform(-1, 0, 0, 1, width, 0); break
    case 3: context.setTransform(-1, 0, 0, -1, width, height); break
    case 4: context.setTransform(1, 0, 0, -1, 0, height); break
    case 5: context.setTransform(0, 1, 1, 0, 0, 0); break
    case 6: context.setTransform(0, 1, -1, 0, width, 0); break
    case 7: context.setTransform(0, -1, -1, 0, width, height); break
    case 8: context.setTransform(0, -1, 1, 0, 0, height); break
    default: context.setTransform(1, 0, 0, 1, 0, 0)
  }
  context.drawImage(bitmap, 0, 0, w, h)
  context.setTransform(1, 0, 0, 1, 0, 0)
}

interface HeifImage {
  get_width(): number
  get_height(): number
  is_primary?: () => boolean
  display(target: { data: Uint8ClampedArray; width: number; height: number }, done: (result: { data: Uint8ClampedArray } | null) => void): void
  free?: () => void
}

/** The primary image of a HEIC/HEIF file, decoded by libheif (LGPL-3.0, WASM). */
async function decodeHeif(bytes: Uint8Array, maxPixels: number): Promise<ImageBitmap> {
  const { default: factory } = await import('libheif-js/libheif-wasm/libheif-bundle.mjs')
  const libheif = factory() as { HeifDecoder: new () => { decode(data: Uint8Array): HeifImage[] } }
  const decoded = new libheif.HeifDecoder().decode(bytes)
  try {
    const image = decoded.find((i) => i.is_primary?.()) ?? decoded[0]
    if (!image) throw new Error('HEIF file has no image')
    const width = image.get_width()
    const height = image.get_height()
    if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height) || width < 1 || height < 1 || width * height > maxPixels) {
      throw new Error('image dimensions exceed preview budget')
    }
    const pixels = await new Promise<Uint8ClampedArray>((resolve, reject) => {
      image.display({ data: new Uint8ClampedArray(width * height * 4), width, height }, (result) => {
        if (result) resolve(result.data)
        else reject(new Error('HEIF could not be decoded'))
      })
    })
    return await createImageBitmap(new ImageData(pixels as Uint8ClampedArray<ArrayBuffer>, width, height))
  } finally {
    for (const image of decoded) image.free?.()
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
const MUTED = '#6b7280'
const RULE = '#e5e7eb'
const CODE_BG = '#f3f4f6'
const ACCENT = '#0369a1'

/** Code colours: GitHub's light ones, as the notes preview uses. */
const TOKEN_COLOURS: Record<TokenKind, string> = {
  plain: INK,
  comment: '#6e7781',
  string: '#0a3069',
  number: '#0550ae',
  keyword: '#cf222e',
  function: '#8250df',
}

const SANS = 'system-ui, sans-serif'
const MONO = 'ui-monospace, monospace'

async function drawTextPage(
  text: string,
  mode: 'prose' | 'code',
  maxEdge: number,
  maxOutputBytes: number,
  outputTypes: RasterOutputType[],
  language?: string,
): Promise<void> {
  // A portrait page, 3:4, whose longest side is the budget's.
  const height = maxEdge
  const width = Math.round((maxEdge * 3) / 4)
  const page = layoutTextPage(text, mode, width, height, language)
  const canvas = new OffscreenCanvas(width, height)
  const context = canvas.getContext('2d', { alpha: false })
  if (!context) throw new Error('preview canvas is unavailable')
  context.fillStyle = PAPER
  context.fillRect(0, 0, width, height)
  context.textBaseline = 'top'
  for (const box of page.boxes) {
    context.fillStyle = box.kind === 'code' ? CODE_BG : RULE
    if (box.kind === 'code') {
      context.beginPath()
      context.roundRect(box.x, box.y, box.width, box.height, Math.round(width / 80))
      context.fill()
    } else {
      context.fillRect(box.x, box.y, box.width, box.height)
    }
  }
  for (const line of page.lines) {
    if (line.rule) {
      context.fillStyle = RULE
      context.fillRect(page.margin, line.y, width - page.margin * 2, Math.max(1, Math.round(line.size / 12)))
      continue
    }
    const font = line.mono ? MONO : SANS
    if (line.marker && line.markerX !== undefined) drawMarker(context, line.marker, line.markerX, line.y, line.size, font)
    context.font = `${line.bold ? '600 ' : ''}${line.size}px ${font}`
    if (line.tokens) {
      // Coloured runs, one after another.
      let x = line.x
      for (const token of line.tokens) {
        context.fillStyle = TOKEN_COLOURS[token.kind]
        context.fillText(token.text, x, line.y)
        x += context.measureText(token.text).width
      }
      continue
    }
    context.fillStyle = line.muted ? MUTED : INK
    context.fillText(line.text, line.x, line.y)
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

/** A list item's bullet or number, or a task's box (ticked when done). */
function drawMarker(
  context: OffscreenCanvasRenderingContext2D,
  marker: NonNullable<PageLine['marker']>,
  x: number,
  y: number,
  size: number,
  font: string,
): void {
  if (marker.kind === 'number') {
    context.fillStyle = MUTED
    context.font = `${size}px ${font}`
    context.fillText(marker.text, x, y)
    return
  }
  if (marker.kind === 'bullet') {
    context.fillStyle = MUTED
    context.beginPath()
    context.arc(x + size * 0.3, y + size * 0.55, Math.max(1, size * 0.16), 0, Math.PI * 2)
    context.fill()
    return
  }
  const box = Math.round(size * 0.85)
  const top = y + Math.round(size * 0.12)
  context.lineWidth = Math.max(1, size / 10)
  if (marker.checked) {
    context.fillStyle = ACCENT
    context.beginPath()
    context.roundRect(x, top, box, box, box / 5)
    context.fill()
    context.strokeStyle = PAPER
    context.beginPath()
    context.moveTo(x + box * 0.22, top + box * 0.52)
    context.lineTo(x + box * 0.42, top + box * 0.72)
    context.lineTo(x + box * 0.78, top + box * 0.3)
    context.stroke()
  } else {
    context.strokeStyle = MUTED
    context.beginPath()
    context.roundRect(x, top, box, box, box / 5)
    context.stroke()
  }
}

function post(message: RasterPreviewWorkerResponseV1, transfer: Transferable[] = []): void {
  self.postMessage(message, { transfer })
}
