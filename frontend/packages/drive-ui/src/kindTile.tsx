import type { FileKind } from '@kutup/drive-core/kinds'
import { KIND_GLYPHS } from './kindGlyphs'

/**
 * A kind's tile as an SVG document, for the browser tab while a file of
 * that kind is open (as Google's editors show a sheet in a spreadsheet's
 * tab). The colours are the theme's, read from the page; the glyph is the
 * same one the lists show.
 */
export async function kindTileSvg(kind: FileKind): Promise<string> {
  const { renderToStaticMarkup } = await import('react-dom/server')
  const styles = getComputedStyle(document.documentElement)
  const tile = styles.getPropertyValue(`--kind-${kind}`).trim() || '#64748b'
  const glyph = styles.getPropertyValue('--kind-glyph').trim() || '#ffffff'
  const Glyph = KIND_GLYPHS[kind]
  const symbol = renderToStaticMarkup(
    <Glyph x={6} y={6} width={20} height={20} color={glyph} strokeWidth={2.25} fill={kind === 'video' ? glyph : 'none'} />,
  )
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="${tile}"/>${symbol}</svg>`
}
