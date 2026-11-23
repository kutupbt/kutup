import type { useTranslation } from 'react-i18next'
import type { SieveProblem } from '@kutup/mail-core/sieve'

/** Sieve's actions Kutup has as features of their own, and where they live. */
const ELSEWHERE: Record<string, 'autoReply' | 'forwarding'> = {
  vacation: 'autoReply',
  redirect: 'forwarding',
}

type Translate = ReturnType<typeof useTranslation>['t']

/** A problem in words: what is wrong, and the text it is about. */
export function problemText(problem: SieveProblem, t: Translate): string {
  const elsewhere = problem.kind === 'unsupported' ? ELSEWHERE[problem.what] : undefined
  if (elsewhere) return t(`sieve.editor.elsewhere.${elsewhere}`)
  if (problem.kind === 'unknownPlace') return `${t('sieve.editor.unknownPlace')} ${problem.what}`
  return `${t(`sieve.problem.${problem.kind}`)} ${problem.what}`
}
