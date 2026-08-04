-- Let the operator clear a processed trace out of the working list without
-- destroying it. Archiving is reversible; DELETE remains the permanent option.
ALTER TABLE trace ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS trace_active
    ON trace (uploaded_at DESC)
    WHERE archived_at IS NULL;
