#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <site>"
    exit 1
fi

site="$1"
mkdir -p "$site"

echo "[+] Subdomain Gathering: $site ..."
curl -s "https://crt.sh/?q=$site&output=json" \
| jq . \
| grep name \
| cut -d":" -f2 \
| grep -v "CN=" \
| cut -d'"' -f2 \
| awk '{gsub(/\\n/,"\n");}1;' \
| sort -u \
> "$site/subdomain_$site.txt"

echo "[+] Saved subdomains: $site/subdomain_$site.txt"

echo "[+] Finding IP Address: $site..."
while read -r sub; do
    host "$sub" 2>/dev/null \
    | grep "has address" \
    | grep "$site" \
    | awk '{print $1, $4}'
done < "$site/subdomain_$site.txt" > "$site/ip_address.txt"

echo "[+] Saved IP: $site/ip_address.txt"

