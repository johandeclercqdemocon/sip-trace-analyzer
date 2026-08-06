#!/usr/bin/env bash
# Download the RFC corpus and IANA registries the knowledge base is built from.
# Idempotent: existing files are kept, so re-running only fetches what is missing.
set -euo pipefail
cd "$(dirname "$0")/.."

RFCS=(3261 3262 3263 3264 3265 3311 3323 3325 3326 3327 3329 3515 3550 3581 3665
      3960 3611
      3711 3725 3856 3891 3892 3903 4028 4566 4733 5359 5626 5806 6026 6141 6337
      7315 8760 8866)
# IANA sip-parameters: 2=headers 3=reason 4=option-tags 5=warn 6=methods
# 7=response codes 8=privacy 9=sec-mech 10=compression 11=uri-params
IANA=(2 3 4 5 6 7 8 9 10 11)

mkdir -p rfc iana

for n in "${RFCS[@]}"; do
    [ -s "rfc/rfc$n.txt" ] && continue
    echo "fetching RFC $n"
    curl -fsS -o "rfc/rfc$n.txt" "https://www.rfc-editor.org/rfc/rfc$n.txt"
done

for f in "${IANA[@]}"; do
    [ -s "iana/sip-parameters-$f.csv" ] && continue
    echo "fetching IANA sip-parameters-$f"
    curl -fsS -o "iana/sip-parameters-$f.csv" \
        "https://www.iana.org/assignments/sip-parameters/sip-parameters-$f.csv"
done

# BSD wc (macOS) pads its output with spaces; tr keeps the arithmetic and the
# message clean on both platforms.
count=$(find rfc -name '*.txt' | wc -l | tr -d '[:space:]')
registries=$(find iana -name '*.csv' | wc -l | tr -d '[:space:]')
[ "$count" -eq "${#RFCS[@]}" ] || { echo "expected ${#RFCS[@]} RFCs, have $count" >&2; exit 1; }
echo "corpus complete: $count RFCs, $registries registries"
