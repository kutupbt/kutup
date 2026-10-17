/**
 * Whether reopening a document drops edits this tab made: the room's base
 * was reset under it (the file was replaced from Drive, or restored to a
 * version in another tab) while some of its edits had not reached the
 * server, or (a whiteboard) something drawn here was not saved yet. Those
 * were made against the content that is gone, so they are not kept — the
 * person is told. A reopen for any other reason (a session that started
 * elsewhere, a trimmed log) keeps the queue.
 */
export function lostUnsentEdits(reset: boolean, unsentEdits: number, unsavedDrawing = false): boolean {
  return reset && (unsentEdits > 0 || unsavedDrawing)
}
