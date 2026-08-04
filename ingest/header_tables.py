"""Parse RFC 3261 Tables 2 and 3 (header field applicability) into rows.

The tables are column-aligned, so slice by column rather than by whitespace:
'where' values like 'r' (response) are otherwise indistinguishable from proxy
flags like 'r' (may reorder).
"""
from __future__ import annotations

import re

METHODS = ["ACK", "BYE", "CAN", "INV", "OPT", "REG"]
VALID_REQ = {"m", "m*", "o", "c", "t", "*", "-"}
TABLE_HEADER = re.compile(r"Header field\s+where\s+proxy\s+ACK BYE CAN INV OPT REG")


# The six requirement cells are the trailing whitespace-separated tokens.
TAIL = re.compile(r"\s((?:m\*|m|o|c|t|\*|-)(?:\s+(?:m\*|m|o|c|t|\*|-)){5})\s*$")


def parse(raw: str) -> list[dict]:
    lines = raw.splitlines()
    rows: list[dict] = []
    for i, line in enumerate(lines):
        if not TABLE_HEADER.search(line):
            continue
        # 'where' and 'proxy' are split by column: a lone 'r' means "response" in
        # the where column but "may reorder" in the proxy column.
        where_col = line.index("where") - 2
        proxy_col = line.index("proxy") - 2
        last_header = None
        for body in lines[i + 1:]:
            if body.strip().startswith("Table "):
                break
            if body.strip().startswith("___"):
                continue  # the rule under the column labels
            m = TAIL.search(body)
            if not m:
                continue  # page furniture, blank line, or a wrapped note
            reqs = m.group(1).split()
            prefix = body[:m.start()].ljust(proxy_col)
            name = prefix[:where_col].strip()
            where = prefix[where_col:proxy_col].strip()
            proxy = prefix[proxy_col:].strip()
            # Retry-After's long status-code list starts left of the 'where'
            # column and bleeds into the name cell; hand the overflow back.
            if " " in name:
                name, overflow = name.split(None, 1)
                where = overflow + where
            if name:
                last_header = name
            elif last_header is None:
                continue
            # A continuation row (Retry-After's extra code lists) reuses the name.
            rows.append({
                "header": last_header,
                "where": where or "any",
                "proxy": proxy or None,
                "requirements": dict(zip(METHODS, reqs, strict=True)),
            })
    return rows


if __name__ == "__main__":
    import pathlib
    import sys

    data = parse(pathlib.Path(sys.argv[1]).read_text())
    for r in data:
        print(f"{r['header']:<22} {r['where']:<12} {r['proxy'] or '':<4} {r['requirements']}")
    print(f"\n{len(data)} rows")
