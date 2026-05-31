#!/usr/bin/env sh
set -eu

GATEWAY="${GATEWAY:-http://localhost:18081}"
HOST_HEADER="${HOST_HEADER:-example.local}"

request() {
  name="$1"
  expected="$2"
  shift 2
  code="$(curl -s -o /tmp/litewaf-sample.out -w '%{http_code}' -H "Host: ${HOST_HEADER}" "$@")"
  printf '%-18s expected=%s actual=%s\n' "$name" "$expected" "$code"
  if [ "$code" != "$expected" ]; then
    printf 'Response body:\n'
    cat /tmp/litewaf-sample.out
    printf '\n'
    exit 1
  fi
}

request "normal" "200" "${GATEWAY}/echo"
request "sqli" "403" "${GATEWAY}/?q=union%20select"
request "xss" "403" "${GATEWAY}/?q=%3Cscript%3Ealert(1)%3C/script%3E"
request "rce" "403" "${GATEWAY}/?cmd=%3Bcat%20/etc/passwd"

printf 'LiteWaf validation samples passed.\n'
