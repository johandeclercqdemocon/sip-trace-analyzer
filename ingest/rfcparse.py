"""Turn plain-text RFCs into sections and RFC 2119 normative rules."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Page furniture emitted by the RFC formatter.
PAGE_BREAK = re.compile(r"\f")
FOOTER = re.compile(r"^\s*\S.*\[Page \d+\]\s*$")
HEADER = re.compile(r"^RFC \d+\s{2,}.*\d{4}\s*$")

# "17.1.1.2 Formal Description" or "A Table of Timer Values", always at column 0.
SECTION = re.compile(r"^(\d+(?:\.\d+)*)\.?\s+(\S.*?)\s*$")
APPENDIX = re.compile(r"^([A-Z](?:\.\d+)*)\.?\s+(\S.{3,}?)\s*$")

KEYWORDS = [
    "MUST NOT", "SHALL NOT", "SHOULD NOT", "NOT RECOMMENDED",
    "MUST", "SHALL", "SHOULD", "REQUIRED", "RECOMMENDED", "MAY", "OPTIONAL",
]
STRENGTH = {
    "MUST": "required", "SHALL": "required", "REQUIRED": "required",
    "MUST NOT": "required", "SHALL NOT": "required",
    "SHOULD": "recommended", "RECOMMENDED": "recommended",
    "SHOULD NOT": "recommended", "NOT RECOMMENDED": "recommended",
    "MAY": "optional", "OPTIONAL": "optional",
}

TOPIC_PATTERNS = {
    "ack": r"\bACK\b",
    "invite": r"\bINVITE\b",
    "bye": r"\bBYE\b",
    "cancel": r"\bCANCEL\b",
    "register": r"\bREGISTER\b|\bregistrar\b",
    "options": r"\bOPTIONS\b",
    "prack": r"\bPRACK\b|100rel",
    "refer": r"\bREFER\b",
    "update": r"\bUPDATE\b",
    "subscribe": r"\bSUBSCRIBE\b|\bNOTIFY\b",
    "via": r"\bVia\b|\bbranch\b|\bmagic cookie\b|\brport\b",
    "route": r"\bRoute\b|\bRecord-Route\b|\bloose rout|\bstrict rout",
    "contact": r"\bContact\b",
    "dialog": r"\bdialog\b",
    "transaction": r"\btransaction\b",
    "timer": r"\bTimer [A-K]\b|\bT1\b|\bT2\b|\bT4\b|\btimer\b",
    "retransmit": r"\bretransmi",
    "sdp": r"\bSDP\b|session description|\boffer\b|\banswer\b",
    "media": r"\bRTP\b|\bRTCP\b|\bmedia stream\b|\bcodec\b",
    "auth": r"\bauthenticat|\bAuthorization\b|\bnonce\b|\bdigest\b",
    "nat": r"\breceived\b|\brport\b|\bsymmetric\b",
    "cseq": r"\bCSeq\b",
    "callid": r"\bCall-ID\b",
    "tag": r"\btag\b",
    "maxforwards": r"\bMax-Forwards\b",
    "proxy": r"\bproxy\b|\bproxies\b",
    "forking": r"\bfork",
    "transport": r"\bUDP\b|\bTCP\b|\bTLS\b|\bSCTP\b|\btransport\b",
    "sessiontimer": r"Session-Expires|\bsession timer|\bMin-SE\b",
    "response": r"\b[1-6]xx\b|\b\d{3} \(",
}
TOPIC_RE = {k: re.compile(v, re.I if k not in ("via", "route", "contact") else 0)
            for k, v in TOPIC_PATTERNS.items()}

# Abbreviations that must not end a sentence.
ABBREV = re.compile(r"(e\.g|i\.e|etc|vs|cf|Fig|Sec|No|Mr|Dr|St|al)\.$")


@dataclass
class Section:
    number: str
    title: str
    depth: int
    start_line: int
    end_line: int
    lines: list[str] = field(default_factory=list)

    @property
    def body(self) -> str:
        return "\n".join(self.lines).strip("\n")


def depaginate(raw: str) -> list[tuple[int, str]]:
    """Drop page furniture, keeping each surviving line's original 1-based number."""
    out: list[tuple[int, str]] = []
    for i, line in enumerate(raw.splitlines(), start=1):
        line = PAGE_BREAK.sub("", line)
        if FOOTER.match(line) or HEADER.match(line):
            continue
        out.append((i, line.rstrip()))
    return out


def rfc_title(raw: str) -> str:
    """Title block sits between the header block and the 'Status of this Memo'."""
    lines = [line.strip() for line in raw.splitlines()[:40]]
    skip = (r"^(Network Working Group|Request for Comments|Category|Updates|"
            r"Obsoletes|Internet Engineering|[A-Z]\. \w+|\w+ \d{4}$)")
    cand = [line for line in lines if line and not re.match(skip, line)]
    # The title is the first centred line that isn't authorship metadata.
    for line in cand:
        if len(line) > 8 and not re.match(r"^[A-Z][a-z]+(, )?", line[:12]) or ":" in line:
            return line
    return cand[0] if cand else "unknown"


def find_toc_end(lines: list[tuple[int, str]]) -> int:
    """Index after the table of contents, so TOC entries aren't mistaken for sections."""
    seen_toc = False
    for idx, (_, line) in enumerate(lines):
        if re.match(r"^\s*Table of Contents", line):
            seen_toc = True
            continue
        if seen_toc and SECTION.match(line):
            return idx  # first column-0 heading after the TOC
    return 0


def parse_sections(raw: str) -> list[Section]:
    lines = depaginate(raw)
    start_idx = find_toc_end(lines)
    sections: list[Section] = []
    cur: Section | None = None

    for idx in range(start_idx, len(lines)):
        lineno, line = lines[idx]
        m = SECTION.match(line) or APPENDIX.match(line)
        is_heading = False
        if m and not line.startswith(" "):
            num, title = m.group(1), m.group(2)
            # Headings are short, title-ish, and followed by a blank line.
            nxt = lines[idx + 1][1] if idx + 1 < len(lines) else ""
            if len(title) < 80 and not title.endswith(",") and (nxt.strip() == "" or nxt.startswith(" ")):
                is_heading = True
        if is_heading:
            if cur:
                cur.end_line = lineno - 1
                sections.append(cur)
            num, title = m.group(1), m.group(2)
            cur = Section(num, title, num.count(".") + 1, lineno, lineno)
        elif cur:
            cur.lines.append(line)

    if cur:
        cur.end_line = lines[-1][0] if lines else cur.start_line
        sections.append(cur)
    return [s for s in sections if s.body.strip()]


def paragraphs(body: str) -> list[str]:
    """Join wrapped lines into paragraphs; keep indented blocks (diagrams) out."""
    paras, buf = [], []
    for line in body.splitlines():
        if not line.strip():
            if buf:
                paras.append(" ".join(buf))
                buf = []
            continue
        # ASCII art / code blocks: heavy indentation plus box characters.
        if re.search(r"[|+_]{3,}|-{5,}", line):
            if buf:
                paras.append(" ".join(buf))
                buf = []
            continue
        buf.append(line.strip())
    if buf:
        paras.append(" ".join(buf))
    return paras


def sentences(para: str) -> list[str]:
    out, buf = [], ""
    for token in re.split(r"(?<=[.!?])\s+", para):
        buf = (buf + " " + token).strip() if buf else token
        if ABBREV.search(buf) or re.search(r"\b(Section|Sections|RFC|Table)\s+[\d.]+$", buf):
            continue
        out.append(buf)
        buf = ""
    if buf:
        out.append(buf)
    return out


def topics_for(text: str) -> list[str]:
    return sorted(k for k, rx in TOPIC_RE.items() if rx.search(text))


def extract_rules(section: Section) -> list[dict]:
    """One row per RFC 2119 keyword occurrence, deduped per sentence+keyword."""
    rules = []
    for para in paragraphs(section.body):
        for sent in sentences(para):
            if len(sent) < 15 or len(sent) > 1200:
                continue
            found: list[str] = []
            for kw in KEYWORDS:
                if re.search(rf"\b{kw}\b", sent):
                    # Skip MUST when it is part of MUST NOT, etc.
                    if kw in ("MUST", "SHALL", "SHOULD", "RECOMMENDED") and any(
                        neg in found for neg in (f"{kw} NOT", "NOT RECOMMENDED")
                    ):
                        continue
                    found.append(kw)
            # Longest match wins for overlapping pairs.
            for kw in list(found):
                if any(other != kw and kw in other for other in found):
                    found.remove(kw)
            for kw in found:
                rules.append({
                    "keyword": kw,
                    "strength": STRENGTH[kw],
                    "text": sent,
                    "topics": topics_for(sent),
                })
    return rules
