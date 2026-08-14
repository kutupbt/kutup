export interface RasterPreviewWorkerRequestV1 {
  type: 'raster-image-v1'
  filename: string
  mimeType: string
  bytes: ArrayBuffer
  maxInputPixels: number
  maxEdge: number
  maxOutputBytes: number
}

export type RasterPreviewWorkerResponseV1 =
  | {
      type: 'raster-image-result-v1'
      raster: ArrayBuffer
      width: number
      height: number
      sourceWidth: number
      sourceHeight: number
    }
  | { type: 'error'; message: string }
