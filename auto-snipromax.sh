#!/bin/bash
# AUTO SNIV PRO — Hybrid Triple Engine (PRO)
# Name: auto-sniv-pro.sh
# Usage: ./auto-sniv-pro.sh -l sni.txt -t 40 -o out
# Stable parsing, minimal false FAIL, human + JSON output.

set -uo pipefail

# ---------- default config ----------
THREAD=30
TIMEOUT=8
INPUT=""
OUTDIR="out"
AUTO_INSTALL=false   # jangan auto install by default

GREEN="\e[32m"; YELLOW="\e[33m"; RED="\e[31m"; NC="\e[0m"

usage(){
  cat <<EOF
AUTO SNIV PRO
Usage: $0 [-l sni.txt] [-t threads] [-o outdir] [--install]
Defaults: input=sni.txt, threads=$THREAD, outdir=$OUTDIR
Options:
  -l FILE     daftar SNI (one per line)
  -t N        threads/concurrency
  -o DIR      output folder
  --install   if set, try install httpx (only if 'go' exists) - best-effort
  -h|--help   show this help
EOF
}

# ---------- parse args ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -l) INPUT="$2"; shift 2;;
    -t) THREAD="$2"; shift 2;;
    -o) OUTDIR="$2"; shift 2;;
    --install) AUTO_INSTALL=true; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 1;;
  esac
done

# default input
if [[ -z "$INPUT" ]]; then
  [[ -f "sni.txt" ]] && INPUT="sni.txt"
fi

if [[ -z "$INPUT" || ! -f "$INPUT" ]]; then
  echo -e "${YELLOW}Input file tidak ditemukan.${NC}"
  read -rp "Masukkan path file SNI: " INPUT
fi

if [[ ! -f "$INPUT" ]]; then
  echo -e "${RED}File tetap tidak ditemukan. Keluar.${NC}"; exit 1
fi

mkdir -p "$OUTDIR"
OKFILE="$OUTDIR/ok.txt"
FAILFILE="$OUTDIR/fail.txt"
DETAILS="$OUTDIR/details.jsonl"
> "$OKFILE"; > "$FAILFILE"; > "$DETAILS"

# ---------- optional install (best-effort) ----------
if [[ "$AUTO_INSTALL" == "true" || "$AUTO_INSTALL" == "True" ]]; then
  # only try if in Termux-like (pkg exists) or go exists for httpx
  if command -v go &>/dev/null; then
    if ! command -v httpx &>/dev/null; then
      echo -e "${YELLOW}[INSTALL] Installing httpx via go (best-effort)${NC}"
      go install github.com/projectdiscovery/httpx/cmd/httpx@latest >/dev/null 2>&1 || true
      cp -f "$HOME/go/bin/httpx" "${PREFIX:-$HOME}/bin/" 2>/dev/null || true
    fi
  fi
fi

# ---------- engine checks ----------
have_curl=false; have_openssl=false; have_httpx=false
command -v curl &>/dev/null && have_curl=true
command -v openssl &>/dev/null && have_openssl=true
command -v httpx &>/dev/null && have_httpx=true

# ---------- helper: escape JSON string ----------
json_escape(){ printf '%s' "$1" | python -c 'import sys,json; print(json.dumps(sys.stdin.read()))' 2>/dev/null || printf '%s' "$1" | sed 's/\"/\\"/g; s/\\/\\\\/g'; }

# ---------- engine implementations ----------
# 1) openssl check: returns 0 on handshake success, writes TLS/proto/cipher to stdout (first line)
openssl_check(){
  host="$1"
  # use timeout if available
  if command -v timeout &>/dev/null; then
    out=$(timeout "$TIMEOUT" openssl s_client -connect "$host:443" -servername "$host" -brief </dev/null 2>/dev/null || true)
  else
    out=$(openssl s_client -connect "$host:443" -servername "$host" -brief </dev/null 2>/dev/null || true)
  fi
  if [[ -z "$out" ]]; then
    return 1
  fi
  # extract protocol/cipher (lines may vary)
  proto=$(printf '%s\n' "$out" | grep -m1 'Protocol' | awk -F': ' '{print $2}' || true)
  cipher=$(printf '%s\n' "$out" | grep -m1 'Cipher' | awk -F': ' '{print $2}' || true)
  # fallback parse "SSL-Session:" block
  if [[ -z "$proto" ]]; then
    proto=$(printf '%s\n' "$out" | grep -Eo 'TLSv1\.[0-9]|TLSv1' | head -n1 || true)
  fi
  printf '%s|%s' "${proto:-unknown}" "${cipher:-unknown}"
  return 0
}

# 2) curl check: get status, remote_ip, time_total, and some headers
curl_check(){
  host="$1"
  # use HEAD first, fallback to GET
  out=$(curl -I --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" -sS -L -A "Mozilla/5.0" "https://$host" 2>/dev/null)
  code=$(printf '%s\n' "$out" | awk 'BEGIN{code=0} /HTTP\/[0-9.]/ {code=$2} END{print code}')
  # remote IP and time via separate curl -w (fast)
  stats=$(curl -sS -o /dev/null -w "%{http_code} %{remote_ip} %{time_total}" --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" -L -A "Mozilla/5.0" "https://$host" 2>/dev/null || true)
  rc=$(printf '%s' "$stats" | awk '{print $1}')
  rip=$(printf '%s' "$stats" | awk '{print $2}')
  ttot=$(printf '%s' "$stats" | awk '{print $3}')
  # server header
  server=$(printf '%s\n' "$out" | grep -i '^Server:' | head -n1 | awk -F': ' '{print $2}' || true)
  # title via HTML title tag (if we did GET)
  title=$(printf '%s\n' "$out" | tr '\r' '\n' | sed -n '1,200p' | grep -iPo '(?<=<title>).*?(?=</title>)' | head -n1 || true)
  # CDN heuristics: presence of CF- headers
  cdn="none"
  if printf '%s\n' "$out" | grep -qi 'cf-ray\|server:.*cloudflare'; then cdn="cloudflare"; fi
  if printf '%s\n' "$out" | grep -qi 'akamai\|akamai\-'; then cdn="akamai"; fi
  # return as: code|rip|ttot|server|title|cdn
  printf '%s|%s|%s|%s|%s|%s' "${rc:-$code}" "${rip:-unknown}" "${ttot:-0}" "${server:-unknown}" "${title:-}" "${cdn}"
  # success if rc starts with 2 or 3
  if [[ "${rc:-$code}" =~ ^2|^3 ]]; then return 0; else return 1; fi
}

# 3) httpx check (optional): return title/cdn/ip/status etc (not relied upon)
httpx_check(){
  host="$1"
  out=$(echo "$host" | httpx -silent -status-code -title -server -ip -cdn -tls-probe -no-color 2>/dev/null || true)
  printf '%s' "$out"
  if [[ -n "$out" ]]; then return 0; else return 2; fi
}

# ---------- combined hybrid test ----------
hybrid_test(){
  host="$1"
  host_trim=$(printf '%s' "$host" | tr -d '\r' | xargs)
  [[ -z "$host_trim" ]] && return

  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  # defaults
  ok_reason=""
  openssl_info=""; curl_info=""; httpx_info=""

  # 1) try openssl (fast check of TLS handshake)
  if $have_openssl; then
    openssl_info=$(openssl_check "$host_trim" || true)
    if [[ -n "$openssl_info" ]]; then
      ok_reason="openssl"
    fi
  fi

  # 2) try curl (HTTP headers and IP)
  curl_info=$(curl_check "$host_trim" || true)
  # parse curl_info
  curl_code=$(printf '%s' "$curl_info" | awk -F'|' '{print $1}')
  curl_ip=$(printf '%s' "$curl_info" | awk -F'|' '{print $2}')
  curl_time=$(printf '%s' "$curl_info" | awk -F'|' '{print $3}')
  curl_server=$(printf '%s' "$curl_info" | awk -F'|' '{print $4}')
  curl_title=$(printf '%s' "$curl_info" | awk -F'|' '{print $5}')
  curl_cdn=$(printf '%s' "$curl_info" | awk -F'|' '{print $6}')

  if [[ -z "$ok_reason" ]]; then
    if [[ "$curl_code" =~ ^2|^3 ]]; then
      ok_reason="curl"
    fi
  fi

  # 3) httpx enrichment (optional)
  if $have_httpx; then
    httpx_info=$(httpx_check "$host_trim" || true)
  fi

  # final decision
  if [[ -n "$ok_reason" ]]; then
    # OK
    echo -e "${GREEN}[OK][${ok_reason}]${NC} $host_trim"
    printf "  IP      : %s\n" "${curl_ip:-unknown}"
    printf "  Status  : %s\n" "${curl_code:-unknown}"
    # parse openssl_info into proto|cipher
    proto=$(printf '%s' "$openssl_info" | awk -F'|' '{print $1}' || true)
    cipher=$(printf '%s' "$openssl_info" | awk -F'|' '{print $2}' || true)
    printf "  TLS     : %s\n" "${proto:-unknown}"
    printf "  Cipher  : %s\n" "${cipher:-unknown}"
    printf "  Server  : %s\n" "${curl_server:-unknown}"
    printf "  Title   : %s\n" "${curl_title:-}"
    printf "  CDN     : %s\n" "${curl_cdn:-none}"
    printf "  Latency : %ss\n" "${curl_time:-0}"
    echo "----------------------------------------"

    # write outputs
    echo "$host_trim" >> "$OKFILE"

    # write JSON line (escaped)
    esc_title=$(json_escape "$curl_title")
    esc_server=$(json_escape "${curl_server:-}")
    esc_proto=$(json_escape "${proto:-}")
    esc_cipher=$(json_escape "${cipher:-}")
    esc_cdn=$(json_escape "${curl_cdn:-}")
    esc_host=$(json_escape "$host_trim")

    printf '{"ts":"%s","host":%s,"ip":"%s","status":"%s","proto":"%s","cipher":"%s","server":%s,"title":%s,"cdn":%s,"latency":"%s","ok_reason":"%s"}\n' \
      "$ts" "$esc_host" "${curl_ip:-unknown}" "${curl_code:-unknown}" "$esc_proto" "$esc_cipher" "$esc_server" "$esc_title" "$esc_cdn" "${curl_time:-0}" "$ok_reason" >> "$DETAILS"

  else
    # FAIL
    echo -e "${RED}[FAIL]${NC} $host_trim"
    echo "$host_trim" >> "$FAILFILE"

    # JSON with failure reason
    esc_host=$(json_escape "$host_trim")
    printf '{"ts":"%s","host":%s,"reason":"no-engine-success"}\n' "$ts" "$esc_host" >> "$DETAILS"
  fi
}

export -f hybrid_test openssl_check curl_check httpx_check json_escape
export OKFILE FAILFILE DETAILS TIMEOUT

# ---------- run multithread ----------
# ensure functions are exported for subshells
cat "$INPUT" | sed 's/\r//g' | xargs -I {} -P "$THREAD" bash -c 'hybrid_test "$@"' _ {}

# ---------- summary ----------
okc=$(wc -l < "$OKFILE" 2>/dev/null || echo 0)
failc=$(wc -l < "$FAILFILE" 2>/dev/null || echo 0)
echo -e "\nDone. OK=$okc FAIL=$failc"
echo "Details JSONL: $DETAILS"
