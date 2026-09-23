-- Folder colours are `#rrggbb` everywhere (the CLI already wrote hex; the
-- web wrote palette names). Map the old names to the colours they showed.
UPDATE collections SET color = CASE color
    WHEN 'purple' THEN '#38bdf8'
    WHEN 'blue'   THEN '#0284c7'
    WHEN 'green'  THEN '#0d9488'
    WHEN 'amber'  THEN '#f59e0b'
    WHEN 'red'    THEN '#ef4444'
    ELSE color
END
WHERE color IN ('purple', 'blue', 'green', 'amber', 'red');

-- Anything else that is not a colour is dropped rather than kept unreadable.
UPDATE collections SET color = lower(color) WHERE color ~ '^#[0-9a-fA-F]{6}$';
UPDATE collections SET color = NULL WHERE color IS NOT NULL AND color !~ '^#[0-9a-f]{6}$';
