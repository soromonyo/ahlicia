#!/bin/sh

HOST=$1

if [ -z "$HOST" ]; then
    echo "Usage: sh bugcheck.sh domain.com"
    exit 1
fi

echo "Menguji host: $HOST"
echo "============================"

PORT80=$(nc -z $HOST 80 2>&1 | grep -c "succeeded")
PORT443=$(nc -z $HOST 443 2>&1 | grep -c "succeeded")

TLS=$(echo | openssl s_client -connect $HOST:443 -servername $HOST 2>/dev/null | grep -c "Verify return code: 0")
CONNECT=$(curl -sx http://$HOST:80 https://google.com -m 5 -k -o /dev/null -w "%{http_code}")
HTTP=$(curl -I -m 5 http://$HOST 2>/dev/null | head -n 1)
HTTPS=$(curl -Ik -m 5 https://$HOST 2>/dev/null | head -n 1)

echo "Port 80 : $( [ $PORT80 -eq 1 ] && echo OPEN || echo CLOSED )"
echo "Port 443: $( [ $PORT443 -eq 1 ] && echo OPEN || echo CLOSED )"
echo "TLS/SNI : $( [ $TLS -eq 1 ] && echo OK || echo FAIL )"
echo "CONNECT : $CONNECT"
echo "HTTP    : $HTTP"
echo "HTTPS   : $HTTPS"

echo "============================"
echo "HASIL AKHIR:"

if [ $TLS -eq 1 ]; then
    echo "✔ VALID BUG SNI (TLS)"
    exit 0
fi

if [ "$CONNECT" = "200" ]; then
    echo "✔ VALID BUG CONNECT (HTTP/Proxy)"
    exit 0
fi

if [ $PORT80 -eq 1 ]; then
    echo "✔ VALID BUG HTTP (non TLS)"
    exit 0
fi

echo "❌ TIDAK BISA DIPAKAI BUG"
exit 1
