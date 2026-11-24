import { linkify } from './linkText'

/** Text with its links clickable, opened in a new tab without the page behind them. */
export function Linkified({ text }: { text: string }) {
  return (
    <>
      {linkify(text).map((piece, index) =>
        piece.kind === 'link' ? (
          <a key={index} href={piece.href} target="_blank" rel="noopener noreferrer" className="break-all text-primary underline underline-offset-2">
            {piece.text}
          </a>
        ) : (
          <span key={index}>{piece.text}</span>
        ),
      )}
    </>
  )
}
