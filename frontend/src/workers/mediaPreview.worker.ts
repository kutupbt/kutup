import { classifyFileForKutup } from '../mediaPreview/fileSafety'
import { inspectRasterDimensions } from '../mediaPreview/imageDimensions'
import type {
  RasterPreviewWorkerRequestV1,
  RasterPreviewWorkerResponseV1,
} from '../mediaPreview/workerProtocol'

const QUALITY_STEPS = [0.82, 0.68, 0.52, 0.38]
const MIN_EDGE = 64

self.onmessage = async (event: MessageEvent<RasterPreviewWorkerRequestV1>) => {
  if (event.origin !== '' && event.origin !== self.location.origin) {
    post({ type: 'error', message: 'Unauthorized origin' })
    return
  }
  try {
    const request = event.data
    if (request.type !== 'raster-image-v1') throw new Error('unknown preview worker request')
    if (!Number.isSafeInteger(request.maxInputPixels) || request.maxInputPixels < 1 ||
        !Number.isSafeInteger(request.maxEdge) || request.maxEdge < 1 ||
        !Number.isSafeInteger(request.maxOutputBytes) || request.maxOutputBytes < 1) {
      throw new Error('invalid preview worker limits')
    }
    if (typeof createImageBitmap !== 'function' || typeof OffscreenCanvas === 'undefined') {
      throw new Error('bounded raster worker is unavailable')
    }
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
        for (const quality of QUALITY_STEPS) {
          const blob = await canvas.convertToBlob({ type: 'image/webp', quality })
          if (blob.type === 'image/webp' && blob.size > 0 && blob.size <= request.maxOutputBytes) {
            const raster = await blob.arrayBuffer()
            post({
              type: 'raster-image-result-v1',
              raster,
              width,
              height,
              sourceWidth: bitmap.width,
              sourceHeight: bitmap.height,
            }, [raster])
            return
          }
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

function post(message: RasterPreviewWorkerResponseV1, transfer: Transferable[] = []): void {
  self.postMessage(message, { transfer })
}
