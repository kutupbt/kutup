-- Back to the web's palette names where a colour matches one; other hex
-- values (set from the CLI) stay, as they did before.
UPDATE collections SET color = CASE color
    WHEN '#38bdf8' THEN 'purple'
    WHEN '#0284c7' THEN 'blue'
    WHEN '#0d9488' THEN 'green'
    WHEN '#f59e0b' THEN 'amber'
    WHEN '#ef4444' THEN 'red'
    ELSE color
END;
