-- SIP knowledge base: everything the trace-analysis bot needs to reason from.
-- Layer 1 (rfc, rfc_section, normative_rule) is mechanically extracted from RFC text.
-- Layer 2 (sip_method, response_code, header_field, header_usage, timer) is structured
--   protocol facts, part extracted / part curated.
-- Layer 3 (diagnostic_check) is the bot's failure-mode catalog, curated and RFC-cited.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ---------------------------------------------------------------- layer 1: source
CREATE TABLE rfc (
    number       INTEGER PRIMARY KEY,
    title        TEXT NOT NULL,
    published    TEXT,
    obsoletes    TEXT,
    obsoleted_by TEXT,
    relevance    TEXT,              -- why this RFC matters to trace analysis
    local_path   TEXT NOT NULL,
    line_count   INTEGER
);

CREATE TABLE rfc_section (
    id           SERIAL PRIMARY KEY,
    rfc_number   INTEGER NOT NULL REFERENCES rfc(number) ON DELETE CASCADE,
    section      TEXT NOT NULL,     -- e.g. "17.1.1.2"
    title        TEXT NOT NULL,
    depth        INTEGER NOT NULL,
    start_line   INTEGER NOT NULL,
    end_line     INTEGER NOT NULL,
    body         TEXT NOT NULL,     -- de-paginated text
    UNIQUE (rfc_number, section)
);
CREATE INDEX rfc_section_body_fts ON rfc_section USING GIN (to_tsvector('english', body));
CREATE INDEX rfc_section_title_trgm ON rfc_section USING GIN (title gin_trgm_ops);

-- Every RFC 2119 normative statement, so a finding can always cite chapter and verse.
CREATE TABLE normative_rule (
    id           SERIAL PRIMARY KEY,
    rfc_number   INTEGER NOT NULL REFERENCES rfc(number) ON DELETE CASCADE,
    section      TEXT NOT NULL,
    section_title TEXT,
    keyword      TEXT NOT NULL,     -- MUST | MUST NOT | SHOULD | SHOULD NOT | MAY | REQUIRED | RECOMMENDED
    strength     TEXT NOT NULL,     -- required | recommended | optional
    text         TEXT NOT NULL,     -- the sentence
    line_no      INTEGER,
    topics       TEXT[] DEFAULT '{}'   -- ack, cancel, via, route, sdp, timer, ...
);
CREATE INDEX normative_rule_kw ON normative_rule (keyword);
CREATE INDEX normative_rule_topics ON normative_rule USING GIN (topics);
CREATE INDEX normative_rule_fts ON normative_rule USING GIN (to_tsvector('english', text));

-- ---------------------------------------------------------------- layer 2: protocol facts
CREATE TABLE sip_method (
    name            TEXT PRIMARY KEY,
    rfc_number      INTEGER REFERENCES rfc(number),   -- set only if in local corpus
    defining_rfc    TEXT,                             -- IANA reference, e.g. 'RFC3515'
    section         TEXT,
    summary         TEXT NOT NULL,
    creates_dialog  BOOLEAN NOT NULL DEFAULT FALSE,
    within_dialog   BOOLEAN NOT NULL DEFAULT FALSE,   -- may be sent inside a dialog
    target_refresh  BOOLEAN NOT NULL DEFAULT FALSE,
    is_invite_txn   BOOLEAN NOT NULL DEFAULT FALSE,
    ack_required    BOOLEAN NOT NULL DEFAULT FALSE,
    cancellable     BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE response_code (
    code               INTEGER PRIMARY KEY,
    class              INTEGER NOT NULL,
    name               TEXT NOT NULL,
    rfc_number         INTEGER REFERENCES rfc(number),
    defining_rfc       TEXT,
    section            TEXT,
    rfc_text           TEXT,          -- verbatim from the RFC
    is_final           BOOLEAN NOT NULL,
    terminates_dialog  BOOLEAN,       -- for an in-dialog request, does this kill the dialog
    -- curated diagnostic layer
    meaning            TEXT,          -- what it really tells you in a trace
    likely_causes      TEXT[] DEFAULT '{}',
    next_checks        TEXT[] DEFAULT '{}',
    who_emits          TEXT,          -- uas | proxy | registrar | either
    severity           TEXT           -- info | warning | error
);

CREATE TABLE header_field (
    name        TEXT PRIMARY KEY,
    compact     TEXT,
    rfc_number  INTEGER REFERENCES rfc(number),
    defining_rfc TEXT,
    section     TEXT,
    summary     TEXT,
    is_dialog_id BOOLEAN NOT NULL DEFAULT FALSE,
    is_routing   BOOLEAN NOT NULL DEFAULT FALSE
);

-- RFC 3261 Tables 2 and 3, machine-readable: which header is mandatory where.
CREATE TABLE header_usage (
    id          SERIAL PRIMARY KEY,
    header      TEXT NOT NULL REFERENCES header_field(name) ON DELETE CASCADE,
    applies_to  TEXT NOT NULL,   -- 'R' (request), 'r' (response), '2xx', '401', '300-699', ...
    method      TEXT NOT NULL,   -- ACK BYE CAN INV OPT REG
    requirement TEXT NOT NULL,   -- m | m* | o | c | t | * | -
    proxy_flags TEXT,            -- a d m r combination from the table
    UNIQUE (header, applies_to, method)
);

CREATE TABLE timer (
    name        TEXT PRIMARY KEY,
    default_value TEXT NOT NULL,
    seconds     NUMERIC,          -- resolved with T1=0.5, T2=4, T4=5 where applicable
    rfc_number  INTEGER REFERENCES rfc(number),
    section     TEXT,
    meaning     TEXT NOT NULL,
    applies_to  TEXT,             -- uac | uas | proxy
    transport   TEXT              -- udp | any
);

-- ---------------------------------------------------------------- layer 3: the bot's rules
CREATE TABLE diagnostic_check (
    id           TEXT PRIMARY KEY,          -- e.g. SIP-ACK-MISSING
    category     TEXT NOT NULL,             -- signalling | media | routing | registration | nat | auth | timer | interop
    severity     TEXT NOT NULL,             -- critical | major | minor | info
    title        TEXT NOT NULL,
    symptom      TEXT NOT NULL,             -- what you see in the trace
    detection    TEXT NOT NULL,             -- how to detect it, plain language / pseudo-conditions
    root_causes  TEXT[] DEFAULT '{}',
    remediation  TEXT,
    rfc_refs     TEXT[] DEFAULT '{}',       -- e.g. {'3261#17.1.1.3','3261#13.2.2.4'}
    confidence   TEXT DEFAULT 'high'        -- how safely this can be auto-asserted
);
CREATE INDEX diagnostic_check_cat ON diagnostic_check (category);

-- Free-text notes that don't fit elsewhere (interop lore, vendor quirks).
CREATE TABLE kb_note (
    id          SERIAL PRIMARY KEY,
    topic       TEXT NOT NULL,
    note        TEXT NOT NULL,
    rfc_refs    TEXT[] DEFAULT '{}',
    source      TEXT
);

-- ---------------------------------------------------------------- uploaded traces
CREATE TABLE trace (
    id           SERIAL PRIMARY KEY,
    filename     TEXT NOT NULL,
    uploaded_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    size_bytes   BIGINT NOT NULL,
    sha256       TEXT NOT NULL,
    kind         TEXT NOT NULL,             -- pcap | text
    stored_path  TEXT NOT NULL,
    report       JSONB,                     -- the analyser's full output
    message_count   INTEGER DEFAULT 0,
    call_count      INTEGER DEFAULT 0,
    finding_count   INTEGER DEFAULT 0,
    worst_severity  TEXT,
    archived_at  TIMESTAMPTZ            -- cleared from the working list, not deleted
);
CREATE INDEX trace_uploaded ON trace (uploaded_at DESC);
CREATE INDEX trace_active ON trace (uploaded_at DESC) WHERE archived_at IS NULL;

-- ---------------------------------------------------------------- LLM quarantine
-- Everything Anthropic returns lands here first. Nothing reaches the curated
-- knowledge base until a human approves it AND its citations resolve.
CREATE TABLE consultation (
    id             SERIAL PRIMARY KEY,
    trace_id       INTEGER REFERENCES trace(id) ON DELETE CASCADE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    model          TEXT NOT NULL,
    served_by      TEXT,                    -- differs from model if a fallback answered
    question       TEXT,
    interpretation TEXT,                    -- the prose answer
    stop_reason    TEXT,
    input_tokens   INTEGER,
    output_tokens  INTEGER,
    cache_read_tokens     INTEGER,
    cache_creation_tokens INTEGER,
    error          TEXT
);

CREATE TABLE kb_fact_candidate (
    id              SERIAL PRIMARY KEY,
    consultation_id INTEGER NOT NULL REFERENCES consultation(id) ON DELETE CASCADE,
    topic           TEXT NOT NULL,
    fact            TEXT NOT NULL,
    rfc_refs        TEXT[] DEFAULT '{}',
    unresolved_refs TEXT[] DEFAULT '{}',    -- citations with no matching rfc_section
    citations_ok    BOOLEAN NOT NULL DEFAULT FALSE,
    status          TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | rejected
    reviewed_at     TIMESTAMPTZ,
    kb_note_id      INTEGER REFERENCES kb_note(id) ON DELETE SET NULL
);
CREATE INDEX kb_fact_candidate_status ON kb_fact_candidate (status);

-- ---------------------------------------------------------------- convenience views
CREATE VIEW v_mandatory_headers AS
SELECT method, applies_to, array_agg(header ORDER BY header) AS headers
FROM header_usage
WHERE requirement IN ('m', 'm*')
GROUP BY method, applies_to;

CREATE VIEW v_rule_search AS
SELECT r.id, r.rfc_number, r.section, r.section_title, r.keyword, r.strength,
       r.topics, r.text,
       'RFC' || r.rfc_number || ' §' || r.section AS citation
FROM normative_rule r;
