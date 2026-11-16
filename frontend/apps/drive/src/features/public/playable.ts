import type { PublicFile } from '@kutup/editors/public/share'
import { chooseViewer } from '@kutup/editors/viewers/dispatch'

/** Whether a public link's file plays here: video and audio do. */
export function playsInPublicPlayer(file: PublicFile): boolean {
  const kind = file.name && file.fileKey && file.content ? chooseViewer(file.name)?.kind : undefined
  return kind === 'video' || kind === 'audio'
}
