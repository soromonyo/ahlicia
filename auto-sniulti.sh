#!/usr/bin/env bash
# auto-sniv-pro-b1.sh
# AUTO SNIV PRO — B1 UI (Border Tebal), Hybrid CDN + TLS Deep, Multi-thread
set -uo pipefail

# ----------- Default config -----------
THREAD=50
TIMEOUT=8
INPUT=""
OUTDIR="out"
DO_BYPASS=false
CSV_OUTPUT=true
JSON_OUTPUT=true
BYPASS_IPS=( "104.17.3.81" "104.21.48.202" "172.67.70.123" "162.159.36.1" )
RETRIES=1

GREEN="\e[32m"; YELLOW="\e[33m"; RED="\e[31m"; BLUE="\e[34m"; NC="\e[0m"

usage(){
  cat <<EOF
AUTO SNIV PRO B1 (UI Tebal)
Usage: $0 [-l sni.txt] [-t threads] [-o outdir] [--bypass] [--no-csv] [--no-json]
Defaults: threads=$THREAD, outdir=$OUTDIR
Options:
  -l FILE       file daftar SNI (one per line)
  -t N          threads
  -o DIR        output folder
  --bypass      enable auto-bypass (try forced resolve list when normal fails)
  --no-csv      disable CSV output
  --no-json     disable JSONL output
  -h|--help     show this help
EOF
}

# ---------- parse args ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -l) INPUT="$2"; shift 2;;
    -t) THREAD="$2"; shift 2;;
    -o) OUTDIR="$2"; shift 2;;
    --bypass) DO_BYPASS=true; shift;;
    --no-csv) CSV_OUTPUT=false; shift;;
    --no-json) JSON_OUTPUT=false; shift;;
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
  read -rp "Masukkan path file SNI (one per line): " INPUT
fi
if [[ ! -f "$INPUT" ]]; then echo -e "${RED}File tetap tidak ditemukan. Keluar.${NC}"; exit 1; fi

mkdir -p "$OUTDIR"
OKFILE="$OUTDIR/ok.txt"
FAILFILE="$OUTDIR/fail.txt"
DETAILS_JSONL="$OUTDIR/details.jsonl"
DETAILS_CSV="$OUTDIR/details.csv"
> "$OKFILE"; > "$FAILFILE"; > "$DETAILS_JSONL"
if $CSV_OUTPUT; then echo "ts,host,ip,status,proto,cipher,cert_sha,server,title,cdn,latency,ok_reason,bypass" > "$DETAILS_CSV"; fi

# ---------- check tools ----------
have_curl=false; have_openssl=false; have_httpx=false; have_python=false; have_timeout=false
command -v curl &>/dev/null && have_curl=true
command -v openssl &>/dev/null && have_openssl=true
command -v httpx &>/dev/null && have_httpx=true
command -v python &>/dev/null && have_python=true
command -v timeout &>/dev/null && have_timeout=true

# ---------- helpers ----------
# minimal json escape: use python if available
json_escape_stream(){
  if $have_python; then
    python -c 'import sys,json; print(json.dumps(sys.stdin.read())[1:-1])'
  else
    sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' -e 's/\r//g' -e 's/\n/\\n/g'
  fi
}

# get openssl TLS info: returns proto|cipher|cert_sha256 or empty on fail
openssl_probe(){
  host="$1"
  if ! $have_openssl; then return 1; fi
  if $have_timeout; then
    raw=$(timeout "$TIMEOUT" openssl s_client -connect "${host}:443" -servername "$host" -tls1_2 </dev/null 2>/dev/null || true)
  else
    raw=$(openssl s_client -connect "${host}:443" -servername "$host" -tls1_2 </dev/null 2>/dev/null || true)
  fi
  [[ -z "$raw" ]] && return 1
  proto=$(printf '%s\n' "$raw" | grep -m1 -E 'Protocol|TLS protocol' | awk -F': ' '{print $2}' || true)
  cipher=$(printf '%s\n' "$raw" | grep -m1 -E '^ *Cipher' | awk -F': ' '{print $2}' || true)
  # fallback simpler parse
  [[ -z "$proto" ]] && proto=$(printf '%s\n' "$raw" | grep -Eo 'TLSv1\.[0-9]|TLSv1' | head -n1 || true)
  # cert
  cert_pem=$(printf '%s\n' "$raw" | awk '/-----BEGIN CERTIFICATE-----/{flag=1} flag{print} /-----END CERTIFICATE-----/{flag=0}' )
  cert_sha="unknown"
  if [[ -n "$cert_pem" ]]; then
    cert_sha=$(printf '%s\n' "$cert_pem" | openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//' | sed 's/://g' || true)
  fi
  printf '%s|%s|%s' "${proto:-unknown}" "${cipher:-unknown}" "${cert_sha:-unknown}"
  return 0
}

# curl probe: returns code|ip|time|server|title|cdn
curl_probe(){
  host="$1"
  # stats
  stats=$(curl -sS -o /dev/null -w "%{http_code}|%{remote_ip}|%{time_total}" --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" -L -A "Mozilla/5.0" "https://$host" 2>/dev/null || true)
  code=$(printf '%s' "$stats" | awk -F'|' '{print $1}')
  rip=$(printf '%s' "$stats" | awk -F'|' '{print $2}')
  ttot=$(printf '%s' "$stats" | awk -F'|' '{print $3}')
  headout=$(curl -I --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" -sS -L -A "Mozilla/5.0" "https://$host" 2>/dev/null || true)
  server=$(printf '%s\n' "$headout" | grep -i '^Server:' | head -n1 | awk -F': ' '{print $2}' || true)
  # small GET to find title (limit bytes)
  title=$(curl -sS --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" -L -A "Mozilla/5.0" "https://$host" 2>/dev/null | tr '\n' ' ' | sed -n '1,400p' | grep -iPo '(?<=<title>).*?(?=</title>)' | head -n1 || true)
  cdn="none"
  if printf '%s\n' "$headout" | grep -qi 'cf-ray\|cloudflare'; then cdn="cloudflare"; fi
  if printf '%s\n' "$headout" | grep -qi 'akamai\|akamaized'; then cdn="akamai"; fi
  if printf '%s\n' "$headout" | grep -qi 'fastly'; then cdn="fastly"; fi
  printf '%s|%s|%s|%s|%s|%s' "${code:-0}" "${rip:-unknown}" "${ttot:-0}" "${server:-unknown}" "${title:-}" "${cdn:-none}"
  if [[ "${code:-0}" =~ ^2|^3 ]]; then return 0; else return 1; fi
}

# httpx enrichment (optional)
httpx_enrich(){
  host="$1"
  if $have_httpx; then
    echo "$(echo "$host" | httpx -silent -status-code -title -server -ip -cdn -tls-probe -no-color 2>/dev/null || true)"
  fi
}

# ---------- UI box printer (B1 heavy) ----------
# print a heavy border box with header domain and key: value lines
print_box(){
  header="$1"; shift
  lines=( "$@" )
  # compute width (max length)
  max=${#header}
  for l in "${lines[@]}"; do
    len=${#l}
    (( len > max )) && max=$len
  done
  # pad width + 2 spaces
  width=$((max + 2))
  # top
  printf "┏"; for ((i=0;i<width;i++)); do printf "━"; done; printf "┓\n"
  # header line (left aligned)
  printf "┃ %-*s ┃\n" "$max" "$header"
  # separator
  printf "┣"; for ((i=0;i<width;i++)); do printf "━"; done; printf "┫\n"
  # content lines
  for l in "${lines[@]}"; do
    printf "┃ %-*s ┃\n" "$max" "$l"
  done
  # bottom
  printf "┗"; for ((i=0;i<width;i++)); do printf "━"; done; printf "┛\n"
}

# ---------- hybrid test ----------
hybrid_test(){
  host="$1"
  host=$(printf '%s' "$host" | tr -d '\r' | xargs)
  [[ -z "$host" ]] && return
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  ok_reason="none"
  bypass_flag="no"

  # try openssl
  proto_cipher_cert=""
  if $have_openssl; then
    proto_cipher_cert=$(openssl_probe "$host" || true)
    if [[ -n "$proto_cipher_cert" ]]; then ok_reason="openssl"; fi
  fi

  # curl probe
  curl_info=$(curl_probe "$host" || true)
  curl_code=$(printf '%s' "$curl_info" | awk -F'|' '{print $1}')
  curl_ip=$(printf '%s' "$curl_info" | awk -F'|' '{print $2}')
  curl_latency=$(printf '%s' "$curl_info" | awk -F'|' '{print $3}')
  curl_server=$(printf '%s' "$curl_info" | awk -F'|' '{print $4}')
  curl_title=$(printf '%s' "$curl_info" | awk -F'|' '{print $5}')
  curl_cdn=$(printf '%s' "$curl_info" | awk -F'|' '{print $6}')

  if [[ "$ok_reason" == "none" && "$curl_code" =~ ^2|^3 ]]; then ok_reason="curl"; fi

  # httpx enrich if available
  httpx_info=""
  if $have_httpx; then httpx_info=$(httpx_enrich "$host" || true); fi

  # if still none and bypass requested, try forced resolves
  if [[ "$ok_reason" == "none" && "$DO_BYPASS" == true ]]; then
    for ip in "${BYPASS_IPS[@]}"; do
      if curl -sS --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" --resolve "$host:443:$ip" -I -L "https://$host" >/dev/null 2>&1; then
        bypass_flag="yes"; ok_reason="bypass"; curl_ip="$ip"; curl_latency="0"
        proto_cipher_cert=$(openssl_probe "$host" || true)
        break
      fi
    done
  fi

  # parse openssl info
  proto=$(printf '%s' "$proto_cipher_cert" | awk -F'|' '{print $1}' || true)
  cipher=$(printf '%s' "$proto_cipher_cert" | awk -F'|' '{print $2}' || true)
  cert_sha=$(printf '%s' "$proto_cipher_cert" | awk -F'|' '{print $3}' || true)

  if [[ "$ok_reason" != "none" ]]; then
    # prepare lines
    lines=()
    lines+=("Status    : ${curl_code:-unknown}")
    lines+=("Title     : ${curl_title:--}")
    lines+=("Server    : ${curl_server:--}")
    lines+=("CDN       : ${curl_cdn:-none}")
    lines+=("IP        : ${curl_ip:-unknown}")
    lines+=("TLS       : ${proto:-unknown}")
    lines+=("Cipher    : ${cipher:-unknown}")
    lines+=("CertSHA   : ${cert_sha:-unknown}")
    lines+=("Latency   : ${curl_latency:-0}s")
    lines+=("Bypass    : ${bypass_flag}")

    # print box (green header)
    header="$(printf '%s' "$host")"
    echo -e "${GREEN}"
    print_box "$header" "${lines[@]}"
    echo -e "${NC}"

    # write files
    echo "$host" >> "$OKFILE"
    # JSONL
    if $JSON_OUTPUT; then
      esc_host=$(printf '%s' "$host" | json_escape_stream)
      esc_server=$(printf '%s' "${curl_server:-}" | json_escape_stream)
      esc_title=$(printf '%s' "${curl_title:-}" | json_escape_stream)
      esc_proto=$(printf '%s' "${proto:-}" | json_escape_stream)
      esc_cipher=$(printf '%s' "${cipher:-}" | json_escape_stream)
      esc_cdn=$(printf '%s' "${curl_cdn:-}" | json_escape_stream)
      printf '{"ts":"%s","host":"%s","ip":"%s","status":"%s","proto":"%s","cipher":"%s","cert_sha":"%s","server":"%s","title":"%s","cdn":"%s","latency":"%s","ok_reason":"%s","bypass":"%s"}\n' \
        "$ts" "$esc_host" "${curl_ip:-unknown}" "${curl_code:-unknown}" "$esc_proto" "$esc_cipher" "${cert_sha:-}" "$esc_server" "$esc_title" "$esc_cdn" "${curl_latency:-0}" "$ok_reason" "$bypass_flag" >> "$DETAILS_JSONL"
    fi
    # CSV
    if $CSV_OUTPUT; then
      printf '"%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s"\n' \
        "$ts" "$host" "${curl_ip:-unknown}" "${curl_code:-unknown}" "${proto:-unknown}" "${cipher:-unknown}" "${cert_sha:-unknown}" "${curl_server:-unknown}" "${curl_title:-}" "${curl_cdn:-none}" "${curl_latency:-0}" "$ok_reason" "$bypass_flag" >> "$DETAILS_CSV"
    fi

  else
    # fail case: print a small red box
    lines=("Status : CONNECTION FAILED" "Bypass : ${bypass_flag}")
    echo -e "${RED}"
    print_box "$host" "${lines[@]}"
    echo -e "${NC}"
    echo "$host" >> "$FAILFILE"
    # JSONL fail
    if $JSON_OUTPUT; then
      esc_host=$(printf '%s' "$host" | json_escape_stream)
      printf '{"ts":"%s","host":"%s","reason":"no-engine-success","bypass":"%s"}\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$esc_host" "$bypass_flag" >> "$DETAILS_JSONL"
    fi
    if $CSV_OUTPUT; then
      printf '"%s","%s","%s","%s"\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$host" "FAIL" "$bypass_flag" >> "$DETAILS_CSV"
    fi
  fi
}

export -f hybrid_test openssl_probe curl_probe httpx_enrich json_escape_stream print_box

# ---------- run multithread (live per domain) ----------
# remove CRLF, feed xargs
cat "$INPUT" | sed 's/\r//g' | xargs -I {} -P "$THREAD" bash -c 'hybrid_test "$@"' _ {}

# ---------- summary ----------
okc=$(wc -l < "$OKFILE" 2>/dev/null || echo 0)
failc=$(wc -l < "$FAILFILE" 2>/dev/null || echo 0)
echo -e "\n${BLUE}Done. OK=$okc FAIL=$failc${NC}"
echo "Files: $OKFILE, $FAILFILE, $DETAILS_JSONL${CSV_OUTPUT:+, $DETAILS_CSV}"
