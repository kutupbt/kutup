/** `label`, with the address the person had before their newest rename. */
export function formerlyLabel(t: (key: string, values?: Record<string, string>) => string, label: string, formerly: string | undefined): string {
  return formerly ? `${label} (${t('identityCheck.renamed.formerly', { formerly })})` : label
}
