import { fromBase64 } from '@kutup/crypto/base64'
import { LINK_PREVIEW_IMAGE_MAX_BYTES, type ChatLinkPreviewV1 } from '@kutup/chat-core/types'
import api from '@kutup/session/client'
import { fitImage } from './avatar'
import { linkify } from '../features/thread/linkify'

// Link previews as Signal makes them: the sender's device builds the preview
// (title, description, a small picture) and sends it inside the encrypted
// message, so recipients never contact the site. A browser cannot read
// another site's page, so this account's server fetches the raw bytes
// (public https only, see docs/chat-protocol.md "Message extras"); the page
// is parsed here by DOMParser, which runs no scripts.

interface Fetched {
  finalUrl: string
  contentType: string
  body: string
}

/** The first https link in the text, as it appears there. */
export function firstPreviewableLink(text: string): string | null {
  for (const part of linkify(text)) {
    if (part.kind === 'link' && part.value.toLowerCase().startsWith('https://')) return part.value
  }
  return null
}

/** Fetch and build a preview for `url`, or null when the page offers none. */
export async function buildLinkPreview(url: string, signal?: AbortSignal): Promise<ChatLinkPreviewV1 | null> {
  const page = (await api.post<Fetched>('/chat/link-preview', { url, kind: 'page' }, { signal })).data
  const html = new TextDecoder().decode(fromBase64(page.body))
  const document = new DOMParser().parseFromString(html, 'text/html')
  const meta = (...names: string[]) => {
    for (const name of names) {
      const element = document.querySelector(`meta[property="${name}"], meta[name="${name}"]`)
      const content = element?.getAttribute('content')?.trim()
      if (content) return content
    }
    return ''
  }
  const title = clip(meta('og:title', 'twitter:title') || document.querySelector('title')?.textContent?.trim() || '', 300)
  if (!title) return null
  const description = clip(meta('og:description', 'twitter:description', 'description'), 1000)
  const preview: ChatLinkPreviewV1 = { url, title, ...(description ? { description } : {}) }
  const imageUrl = meta('og:image', 'og:image:url', 'twitter:image')
  if (imageUrl) {
    try {
      const absolute = new URL(imageUrl, page.finalUrl)
      if (absolute.protocol === 'https:') {
        const image = (await api.post<Fetched>('/chat/link-preview', { url: absolute.href, kind: 'image' }, { signal })).data
        const fitted = await fitImage(new Blob([fromBase64(image.body) as BlobPart], { type: image.contentType }), {
          maxSide: 400,
          maxBytes: LINK_PREVIEW_IMAGE_MAX_BYTES,
        })
        preview.image = { contentType: fitted.contentType, data: fitted.base64 }
      }
    } catch (error) {
      if (signal?.aborted) throw error
      // A preview without its picture is still a preview.
    }
  }
  return preview
}

/** At most `max` characters, whitespace collapsed. */
function clip(value: string, max: number): string {
  const collapsed = value.replace(/\s+/gu, ' ').trim()
  const characters = [...collapsed]
  return characters.length <= max ? collapsed : `${characters.slice(0, max - 1).join('')}…`
}
