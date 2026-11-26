-- Keyboard shortcuts in every app, on or off for the account (Proton's
-- single setting; docs/roadmap.md). Null: never chosen, on.
ALTER TABLE account_ui_preferences ADD COLUMN shortcuts boolean;
