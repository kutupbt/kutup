// KeePass's 69 built-in icons (docs/plans/pass-gaps-3.md, A3, Q-3), drawn
// with Kutup's icon set: each number keeps its meaning (KeePassXC's
// share/icons/database names), and the number is what the vault keeps, so
// other KeePass apps show their own picture for it.

import {
  Apple, Archive, Banknote, BatteryCharging, Bird, BookUser, CalendarDays, Camera, CaseSensitive, ChartPie, CircleCheck, CircleHelp, CircleX,
  Clapperboard, ClipboardList, ConciergeBell, Contact, Disc, Earth, Feather, FileArchive, FileBadge, FileCode, FileText, Fingerprint, Folder,
  FolderOpen, FolderSync, Globe, Hammer, HardDriveDownload, History, House, IdCard, Image, Inbox, KeyRound, KeySquare, Languages, LayoutGrid,
  Library, Lock, LockOpen, Mail, MailSearch, MemoryStick, Monitor, Network, Package, PenTool, Percent, Plug, Printer, Radio, Rocket, Save,
  ScanLine, ScreenShare, Server, Settings, Shapes, Signature, SlidersHorizontal, Smartphone, SquareTerminal, StickyNote, Terminal, Trash2,
  TriangleAlert, type LucideIcon,
} from 'lucide-react'

/** By KeePass's number, 0 (the key) to 68. */
export const BUILTIN_ICONS: readonly LucideIcon[] = [
  KeyRound, Globe, TriangleAlert, Server, ClipboardList, Languages, SlidersHorizontal, FileCode, Plug, IdCard,
  BookUser, Camera, Radio, KeySquare, BatteryCharging, ScanLine, Earth, Disc, Monitor, Mail,
  Shapes, CalendarDays, CaseSensitive, LayoutGrid, Network, Inbox, Save, HardDriveDownload, Clapperboard, SquareTerminal,
  Terminal, Printer, ChartPie, Rocket, Settings, ScreenShare, Archive, Percent, FolderSync, History,
  MailSearch, PenTool, MemoryStick, Trash2, StickyNote, CircleX, CircleHelp, Package, Folder, FolderOpen,
  FileArchive, LockOpen, Lock, CircleCheck, Signature, Image, Contact, FileText, Fingerprint, Hammer,
  House, ConciergeBell, Bird, Feather, Apple, Library, Banknote, FileBadge, Smartphone,
]

/** The entry default (the key) and the group default (the folder). */
export const ENTRY_DEFAULT_ICON = 0
export const GROUP_DEFAULT_ICON = 48

/** The drawing for a built-in number, if there is one. */
export function builtinIcon(number: number | null | undefined): LucideIcon | null {
  return number != null && number >= 0 && number < BUILTIN_ICONS.length ? BUILTIN_ICONS[number] : null
}
