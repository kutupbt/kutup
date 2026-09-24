/** Encodings a worker may produce, in order of preference. */
export type RasterOutputType = 'image/webp' | 'image/jpeg'

export interface RasterPreviewWorkerRequestV1 {
  type: 'raster-image-v1'
  filename: string
  mimeType: string
  bytes: ArrayBuffer
  maxInputPixels: number
  maxEdge: number
  maxOutputBytes: number
  /** Defaults to WebP only (Chat's wire format requires it). */
  outputTypes?: RasterOutputType[]
}

/**
 * A text file drawn as the top of a page: a paper look, the same in both
 * themes, for Drive thumbnails of notes and code.
 */
export interface TextPageWorkerRequestV1 {
  type: 'text-page-v1'
  text: string
  /** `prose`: proportional font, Markdown headings bold; `code`: monospace. */
  mode: 'prose' | 'code'
  maxEdge: number
  maxOutputBytes: number
  outputTypes?: RasterOutputType[]
}

export type PreviewWorkerRequestV1 = RasterPreviewWorkerRequestV1 | TextPageWorkerRequestV1

export type RasterPreviewWorkerResponseV1 =
  | {
      type: 'raster-image-result-v1'
      raster: ArrayBuffer
      contentType: RasterOutputType
      width: number
      height: number
      sourceWidth: number
      sourceHeight: number
    }
  | { type: 'error'; message: string }
