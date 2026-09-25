import type { ComponentType, ReactNode } from 'react'
import {
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuSub,
  ContextMenuSubContent,
  ContextMenuSubTrigger,
} from '@kutup/ui/components/context-menu'
import {
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
} from '@kutup/ui/components/dropdown-menu'

export interface MenuParts {
  Item: ComponentType<{ onSelect?: (event: Event) => void; destructive?: boolean; children?: ReactNode; 'data-testid'?: string }>
  Separator: ComponentType
  Sub: ComponentType<{ children?: ReactNode }>
  SubTrigger: ComponentType<{ children?: ReactNode; 'data-testid'?: string }>
  SubContent: ComponentType<{ children?: ReactNode }>
}

export const DROPDOWN_PARTS: MenuParts = {
  Item: DropdownMenuItem,
  Separator: DropdownMenuSeparator,
  Sub: DropdownMenuSub,
  SubTrigger: DropdownMenuSubTrigger,
  SubContent: DropdownMenuSubContent,
}

export const CONTEXT_PARTS: MenuParts = {
  Item: ContextMenuItem,
  Separator: ContextMenuSeparator,
  Sub: ContextMenuSub,
  SubTrigger: ContextMenuSubTrigger,
  SubContent: ContextMenuSubContent,
}

