import { useSyncExternalStore } from 'react'

/**
 * An upload whose name is taken in its folder by something else
 * (docs/plans/drive-unique-names.md): the person chooses, one question at a
 * time, and may apply the answer to the rest of the batch.
 */

export type ConflictChoice = 'replace' | 'keepBoth' | 'skip'

export interface ConflictQuestion {
  /** The name being uploaded. */
  name: string
  /** The folder it goes into (display only). */
  folderName: string
  /** What holds the name there. */
  holder: 'file' | 'folder'
  /** The name it would take under "Keep both". */
  keptAs: string
  /** Replacing is offered: a file holds the name and the person may move it to the trash. */
  canReplace: boolean
  /** More items of the same batch may still clash ("apply to all" is offered). */
  more: boolean
}

export interface ConflictAnswer {
  choice: ConflictChoice
  /** Apply it to the rest of the batch. */
  all: boolean
}

interface Pending {
  id: number
  question: ConflictQuestion
  resolve: (answer: ConflictAnswer) => void
}

let queue: Pending[] = []
let nextId = 1
const listeners = new Set<() => void>()

function emit(next: Pending[]) {
  queue = next
  for (const l of listeners) l()
}

/** Ask; rejects with an `AbortError` when the upload is cancelled meanwhile. */
export function askNameConflict(question: ConflictQuestion, signal?: AbortSignal): Promise<ConflictAnswer> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException('Upload cancelled', 'AbortError'))
      return
    }
    const id = nextId++
    const done = () => emit(queue.filter((p) => p.id !== id))
    const onAbort = () => {
      done()
      reject(new DOMException('Upload cancelled', 'AbortError'))
    }
    signal?.addEventListener('abort', onAbort, { once: true })
    emit([
      ...queue,
      {
        id,
        question,
        resolve: (answer) => {
          signal?.removeEventListener('abort', onAbort)
          done()
          resolve(answer)
        },
      },
    ])
  })
}

const subscribe = (listener: () => void) => {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

/** The question asked now, and how to answer it; null when none is open. */
export function useNameConflict(): { question: ConflictQuestion; answer: (answer: ConflictAnswer) => void } | null {
  const head = useSyncExternalStore(subscribe, () => queue[0] ?? null)
  return head ? { question: head.question, answer: head.resolve } : null
}

/**
 * One batch's answers: once the person applies a choice to all, the rest of
 * the batch takes it without asking. A choice that does not fit an item
 * (replacing a folder) is asked about again.
 */
export class ConflictPolicy {
  private remembered: ConflictChoice | null = null

  /** `size`: how many items the batch has (no "apply to all" for one). */
  constructor(private readonly size: number) {}

  async choose(question: Omit<ConflictQuestion, 'more'>, signal?: AbortSignal): Promise<ConflictChoice> {
    const remembered = this.remembered
    if (remembered && (remembered !== 'replace' || question.canReplace)) return remembered
    const answer = await askNameConflict({ ...question, more: this.size > 1 }, signal)
    if (answer.all) this.remembered = answer.choice
    return answer.choice
  }
}
