import { Editor } from '@tiptap/react'
import StarterKit from '@tiptap/starter-kit'
import { describe, expect, it } from 'vitest'
import { InlineImage, withContentIds } from './inlineImages'

// A draft's HTML names its inline images as `cid:`, which the page's
// img-src refuses (full test, spec 106): the editor must never render one.
describe('inline images in the editor', () => {
  it('read a cid: image as its part, with no src, and send it as cid: again', () => {
    const editor = new Editor({
      extensions: [StarterKit, InlineImage],
      content: '<p>Bakın: <img src="cid:abc@kutup" alt="kirmizi.png"></p>',
    })
    const img = editor.view.dom.querySelector('img:not(.ProseMirror-separator)')!
    expect(img.getAttribute('src') ?? '').not.toMatch(/^cid:/i)
    let attrs: Record<string, unknown> = {}
    editor.state.doc.descendants((node) => {
      if (node.type.name === 'image') attrs = node.attrs
    })
    expect(attrs.cid).toBe('abc@kutup')
    expect(attrs.src).toBeNull()
    // Sent with its part's cid: again.
    expect(withContentIds(editor.getHTML())).toContain('src="cid:abc@kutup"')
    editor.destroy()
  })

  it('show the blob the composer sets, and send it as cid:', () => {
    const editor = new Editor({ extensions: [StarterKit, InlineImage], content: '<p></p>' })
    editor.commands.insertContent({ type: 'image', attrs: { src: 'blob:https://mail.example/1', cid: 'x@kutup' } })
    expect(editor.view.dom.querySelector('img:not(.ProseMirror-separator)')!.getAttribute('src')).toBe('blob:https://mail.example/1')
    expect(withContentIds(editor.getHTML())).toContain('src="cid:x@kutup"')
    editor.destroy()
  })
})
