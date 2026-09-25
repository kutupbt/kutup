import { useMemo } from 'react'
import { useChat } from '../app/chatStore'
import { foldAccountState, mergeReadMarks, type AccountState } from './accountState'
import { useReadMarks } from './readState'

/** This account's synced list state and read positions, from the loaded history. */
export function useAccountState(): AccountState {
  const { snapshot, self } = useChat()
  const address = self?.address ?? ''
  return useMemo(() => foldAccountState(snapshot.history, address), [snapshot.history, address])
}

/** How far each conversation is read, on this device or another of this account's. */
export function useReadThrough(): Record<string, number> {
  const local = useReadMarks()
  const { readThrough } = useAccountState()
  return useMemo(() => mergeReadMarks(local, readThrough), [local, readThrough])
}
