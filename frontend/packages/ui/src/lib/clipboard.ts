/** Copy text; the Clipboard API needs a secure context, which every Kutup origin is. */
export async function copyText(text: string): Promise<void> {
  await navigator.clipboard.writeText(text)
}
