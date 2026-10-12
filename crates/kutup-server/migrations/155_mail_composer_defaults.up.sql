-- Composer defaults (docs/plans/mail-parity.md, P4), Proton's "Composer
-- mode", "Composer text direction" and "Composer default font/size".
ALTER TABLE mail_settings
    ADD COLUMN draft_type TEXT NOT NULL DEFAULT 'html' CHECK (draft_type IN ('html', 'plain')),
    ADD COLUMN text_direction TEXT NOT NULL DEFAULT 'ltr' CHECK (text_direction IN ('ltr', 'rtl')),
    ADD COLUMN font_face TEXT NOT NULL DEFAULT 'arial' CHECK (font_face IN (
        'sans-serif', 'serif', 'georgia', 'arial', 'helvetica', 'monospace', 'tahoma', 'verdana',
        'times', 'trebuchet')),
    ADD COLUMN font_size INTEGER NOT NULL DEFAULT 14 CHECK (font_size IN (10, 12, 14, 16, 18, 20, 22, 24, 26));
