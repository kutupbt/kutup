// The vault's own pictures (KeePass custom icons; docs/plans/pass.md,
// "Custom icons"). They show as data: addresses (the pass host loads no
// outside images), and a new one is redrawn here as a PNG of at most 64 px a
// side, which also drops anything but the pixels.

import { bytesToBase64 } from './bytes'
import type { CustomIconView, VaultView } from '../vault/types'

/** The largest side a new picture keeps, in pixels. */
export const ICON_PIXELS = 64
/** The largest image read for a picture. */
export const MAX_ICON_SOURCE_BYTES = 5 * 1024 * 1024
/** What the upload offers: raster images a browser reads. */
export const ICON_TYPES = 'image/png,image/jpeg,image/gif,image/webp,image/bmp,image/x-icon,image/vnd.microsoft.icon,.ico'

export function iconSource(icon: CustomIconView): string {
  return `data:${icon.mime};base64,${icon.data}`
}

/** Each picture's image address, by id. */
export function iconSources(view: VaultView): Map<string, string> {
  return new Map(view.customIcons.map((icon) => [icon.id, iconSource(icon)]))
}

export class IconReadError extends Error {}

/** `image` as a PNG (base64) of at most 64 px a side; never enlarged. */
export async function toIconPng(image: Blob): Promise<string> {
  if (image.size === 0 || image.size > MAX_ICON_SOURCE_BYTES || image.type === 'image/svg+xml') throw new IconReadError()
  const address = URL.createObjectURL(image)
  try {
    const img = new Image()
    img.src = address
    await img.decode().catch(() => {
      throw new IconReadError()
    })
    const width = img.naturalWidth
    const height = img.naturalHeight
    if (!width || !height) throw new IconReadError()
    const scale = Math.min(1, ICON_PIXELS / Math.max(width, height))
    const canvas = document.createElement('canvas')
    canvas.width = Math.max(1, Math.round(width * scale))
    canvas.height = Math.max(1, Math.round(height * scale))
    const context = canvas.getContext('2d')
    if (!context) throw new IconReadError()
    context.imageSmoothingQuality = 'high'
    context.drawImage(img, 0, 0, canvas.width, canvas.height)
    const png = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, 'image/png'))
    if (!png) throw new IconReadError()
    return bytesToBase64(new Uint8Array(await png.arrayBuffer()))
  } finally {
    URL.revokeObjectURL(address)
  }
}

/** A picture of the vault as the edit takes it: as it is when a PNG. */
export async function iconPngOf(icon: CustomIconView): Promise<string> {
  if (icon.mime === 'image/png') return icon.data
  const bytes = Uint8Array.from(atob(icon.data), (c) => c.charCodeAt(0))
  return toIconPng(new Blob([bytes], { type: icon.mime }))
}
