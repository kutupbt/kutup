import Image from '@tiptap/extension-image'
import { DOMSerializer } from '@tiptap/pm/model'
import type { Editor } from '@tiptap/react'
import { fetchMailImage } from '@kutup/mail-core/api'

/** Where a remote image keeps its address in the editor's own markup. */
const REMOTE_SRC = 'data-remote-src'

/**
 * TipTap's image, keeping which inline part it shows (`data-cid`). A saved
 * draft's text points at its parts (`cid:`): such an image opens with no
 * address, since a browser can't load `cid:` (and the Content-Security-Policy
 * refuses it), until the draft's parts give it this browser's URL.
 *
 * A remote image in the text (pasted, or quoted from a message) keeps its
 * address in what is sent, but is shown through the Kutup image proxy, as the
 * reader shows one: never loaded from its server by this browser, which
 * would tell that server who is writing and when (and the policy allows no
 * remote images). A tracker or an image the proxy can't get shows its
 * description only.
 */
export const InlineImage = Image.extend({
  addAttributes() {
    return {
      ...this.parent?.(),
      src: {
        default: null,
        parseHTML: (element) => {
          const src = element.getAttribute('src') ?? element.getAttribute(REMOTE_SRC)
          return src?.startsWith('cid:') ? null : src
        },
        // A remote address never becomes an element's src, wherever the
        // editor renders (ProseMirror draws a node without its node view
        // too): editorHtml() gives it back its src in the HTML that is sent.
        renderHTML: (attributes: { src?: string | null }) =>
          !attributes.src ? {} : isRemote(attributes.src) ? { [REMOTE_SRC]: attributes.src } : { src: attributes.src },
      },
      cid: {
        default: null,
        parseHTML: (element) => element.getAttribute('data-cid') ?? contentIdOf(element.getAttribute('src')),
        renderHTML: (attributes: { cid?: string | null }) => (attributes.cid ? { 'data-cid': attributes.cid } : {}),
      },
    }
  },
  parseHTML() {
    return [{ tag: 'img[src]:not([src^="data:"])' }, { tag: `img[${REMOTE_SRC}]` }]
  },
  addNodeView() {
    return ({ node }) => {
      const dom = document.createElement('img')
      // The address this element stands for, and the proxy's copy of it.
      let shown: string | null = null
      let proxied: string | null = null
      const release = () => {
        if (proxied) URL.revokeObjectURL(proxied)
        proxied = null
      }
      const render = (attrs: Record<string, unknown>) => {
        for (const name of ['alt', 'title', 'width', 'height'] as const) {
          const value = attrs[name]
          if (typeof value === 'string' && value !== '') dom.setAttribute(name, value)
          else if (typeof value === 'number') dom.setAttribute(name, String(value))
          else dom.removeAttribute(name)
        }
        const cid = attrs.cid as string | null
        if (cid) dom.setAttribute('data-cid', cid)
        else dom.removeAttribute('data-cid')
        const src = (attrs.src as string | null) ?? null
        if (src === shown) return
        shown = src
        release()
        dom.removeAttribute('src')
        if (!src) return
        if (!isRemote(src)) {
          dom.setAttribute('src', src)
          return
        }
        dom.setAttribute(REMOTE_SRC, src)
        void fetchMailImage(src).then((result) => {
          if (shown !== src || result.kind !== 'image') return
          proxied = URL.createObjectURL(result.blob)
          dom.setAttribute('src', proxied)
        })
      }
      render(node.attrs)
      return {
        dom,
        update: (updated) => {
          if (updated.type !== node.type) return false
          if (updated.attrs.src !== shown) dom.removeAttribute(REMOTE_SRC)
          render(updated.attrs)
          return true
        },
        destroy: () => {
          shown = null
          release()
        },
      }
    }
  },
}).configure({ inline: true, allowBase64: false })

function isRemote(src: string): boolean {
  return /^https?:/i.test(src)
}

function contentIdOf(src: string | null): string | null {
  return src?.startsWith('cid:') ? src.slice('cid:'.length) : null
}

/**
 * The editor's HTML, as `editor.getHTML()` gives it but with each remote
 * image's address back in its src, made in an inert document. TipTap builds that HTML from elements of the page's own document,
 * and an image element there starts loading its address at once, even
 * outside the page: a remote image would be fetched from its server and a
 * `cid:` one refused by the Content-Security-Policy.
 */
export function editorHtml(editor: Editor): string {
  const inert = document.implementation.createHTMLDocument('')
  const fragment = DOMSerializer.fromSchema(editor.schema).serializeFragment(editor.state.doc.content, { document: inert })
  const container = inert.createElement('div')
  container.appendChild(fragment)
  container.querySelectorAll(`img[${REMOTE_SRC}]`).forEach((img) => {
    img.setAttribute('src', img.getAttribute(REMOTE_SRC) ?? '')
    img.removeAttribute(REMOTE_SRC)
  })
  return container.innerHTML
}

/** The editor's HTML as sent: each inline image points at its part (`cid:`), not at this browser's blob. */
export function withContentIds(html: string): string {
  if (!html.includes('data-cid')) return html
  const doc = new DOMParser().parseFromString(html, 'text/html')
  doc.querySelectorAll('img[data-cid]').forEach((img) => {
    img.setAttribute('src', `cid:${img.getAttribute('data-cid')}`)
    img.removeAttribute('data-cid')
  })
  return doc.body.innerHTML
}

/** A new Content-ID for an inline image. */
export const newContentId = () => `${crypto.randomUUID()}@kutup`

/**
 * Proton's "Remove metadata": a JPEG, PNG or WebP drawn again, without
 * EXIF (where, on which device, when). Other images go as they are.
 */
export async function withoutMetadata(file: File): Promise<Uint8Array> {
  const original = new Uint8Array(await file.arrayBuffer())
  if (!['image/jpeg', 'image/png', 'image/webp'].includes(file.type)) return original
  try {
    const bitmap = await createImageBitmap(file)
    const canvas = document.createElement('canvas')
    canvas.width = bitmap.width
    canvas.height = bitmap.height
    canvas.getContext('2d')!.drawImage(bitmap, 0, 0)
    bitmap.close()
    const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, file.type, 0.92))
    return blob ? new Uint8Array(await blob.arrayBuffer()) : original
  } catch {
    return original
  }
}
