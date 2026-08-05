-- Separate the two numbers that were previously conflated in call_count.
--
-- call_count was len(calls) — one per Call-ID. A trunk capture is mostly OPTIONS
-- keepalives and REGISTERs, each with its own Call-ID, so that number ran an
-- order of magnitude above what Wireshark's VoIP Calls window shows and read as
-- a bug. From now on call_count is the INVITE-dialog count and call_id_count is
-- the raw grouping; the GUI shows both.
ALTER TABLE trace ADD COLUMN IF NOT EXISTS call_id_count INTEGER;

-- Backfill from the stored reports. Older reports predate the per-call "kind"
-- field, but 'no INVITE' as an outcome is exactly the same test, so the historic
-- rows land on the same answer a re-analysis would give.
UPDATE trace SET
    call_id_count = COALESCE(call_id_count, call_count),
    call_count = (
        SELECT count(*)
        FROM jsonb_array_elements(COALESCE(report->'calls', '[]'::jsonb)) AS c
        WHERE COALESCE(c->>'kind', CASE WHEN c->>'outcome' = 'no INVITE'
                                        THEN 'other' ELSE 'call' END) = 'call')
WHERE call_id_count IS NULL;
