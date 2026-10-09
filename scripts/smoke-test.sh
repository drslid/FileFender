#!/usr/bin/env bash
# End-to-end check of a running FileFender instance with real engines.
# Usage: FILEFENDER_URL=http://127.0.0.1:8080 FILEFENDER_KEY=ff_... scripts/smoke-test.sh
set -euo pipefail

url="${FILEFENDER_URL:-http://127.0.0.1:8080}"
key="${FILEFENDER_KEY:?set FILEFENDER_KEY to an API key}"
for tool in curl jq zip; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

check() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$actual" == "$expected" ]]; then
    printf '  ok   %s\n' "$name"
  else
    printf '  FAIL %s: expected %s, got %s\n' "$name" "$expected" "$actual"
    failures=$((failures + 1))
  fi
}

scan() {
  curl -sS -H "Authorization: Bearer $key" -F "file=@$1" "$url/v1/scan"
}

echo "FileFender smoke test against $url"

check "healthz" "ok" "$(curl -sS "$url/healthz" | jq -r .status)"
check "readyz" "ready" "$(curl -sS "$url/readyz" | jq -r .status)"
check "account setup state is published" "boolean" "$(curl -sS "$url/v1/setup" | jq -r '.required | type')"
check "scan without a key is refused" "401" \
  "$(curl -sS -o /dev/null -w '%{http_code}' -F "file=@/etc/hostname" "$url/v1/scan")"

# The EICAR test string is assembled at run time so this script never trips scanners.
# shellcheck disable=SC2016 # literal dollar signs
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$work/eicar.com"
printf 'Quarterly report\nNothing to see here.\n' > "$work/report.txt"
(cd "$work" && zip -q eicar.zip eicar.com && zip -q -P infected encrypted.zip report.txt)

check "clean text file" "clean" "$(scan "$work/report.txt" | jq -r .verdict)"
eicar="$(scan "$work/eicar.com")"
check "EICAR is malicious" "malicious" "$(jq -r .verdict <<<"$eicar")"
check "ClamAV detects EICAR" "true" "$(jq '[.threats[] | select(.engine == "clamav")] | length > 0' <<<"$eicar")"
check "EICAR inside a ZIP" "malicious" "$(scan "$work/eicar.zip" | jq -r .verdict)"
check "password-protected ZIP is suspicious" "suspicious" "$(scan "$work/encrypted.zip" | jq -r .verdict)"

raw="$(curl -sS -H "Authorization: Bearer $key" -H 'Content-Type: application/octet-stream' \
  --data-binary "@$work/eicar.com" "$url/v1/scan?filename=raw%20upload.com")"
check "raw body upload" "malicious" "$(jq -r .verdict <<<"$raw")"
check "file name from the query" "raw upload.com" "$(jq -r .file.name <<<"$raw")"
check "repeated file comes from the cache" "true" "$(jq -r .cached <<<"$raw")"

sha="$(jq -r .file.sha256 <<<"$eicar")"
check "hash lookup" "malicious" \
  "$(curl -sS -H "Authorization: Bearer $key" "$url/v1/hashes/$sha" | jq -r .verdict)"

# A Windows program (MZ and PE headers) named like a picture: the default file policy.
{ printf 'MZ'; head -c 58 /dev/zero; printf '\x80\x00\x00\x00'; head -c 64 /dev/zero; printf 'PE\x00\x00'; head -c 256 /dev/zero; } >"$work/holiday.jpg"
check "program disguised as a picture" "Policy.Disguised.Executable" \
  "$(scan "$work/holiday.jpg" | jq -r '[.threats[] | select(.engine == "policy")][0].name')"

limit="$(curl -sS -H "Authorization: Bearer $key" "$url/v1/status" | jq -r .limits.max_file_size)"
check "declared oversized upload is refused" "413" \
  "$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $key" \
     -H 'Content-Type: application/octet-stream' -H "Content-Length: $((limit + 2 * 1024 * 1024))" \
     --data-binary 'x' --max-time 10 "$url/v1/scan" || true)"

status="$(curl -sS -H "Authorization: Bearer $key" "$url/v1/status")"
check "status reports ready" "true" "$(jq -r .ready <<<"$status")"
check "ClamAV signatures loaded" "true" "$(jq '.engines.clamav.signatures > 100000' <<<"$status")"
check "metrics exposed" "1" \
  "$(curl -sS -H "Authorization: Bearer $key" "$url/metrics" | awk '$1 == "filefender_ready" {print $2}')"

if ((failures > 0)); then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all checks passed"
