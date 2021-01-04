#!/bin/bash

source ~/.bash_profiles
echo "[+] Starting subdomain enumeration."

mkdir ultimatesubs
target=$1

echo "[+] Starting sublist3r for subdomain enumeration."
python3 ~/tools/Sublist3r/sublist3r.py -d "$target" -o ultimatesubs/sublist3r.txt

echo "[+] Starting amass for subdomain enumeration."
~/tools/amass_linux_amd64/amass enum -silent  -passive -d  "$target" -o ultimatesubs/amass.txt

echo "[+] Starting find-domain for subdomain enumeration."
~/tools/findomain-linux  -t "$target" -u ultimatesubs/findomain.txt

echo "[+] Running subscraper for subdomain enumeration."
subscraper -t 100 "$target" --censys-api "29c6e13b-bdd2-46d8-b6b7-1f679b4ee70d" --censys-secret "CfEDWOxM2OLR8CYzfNnK0V46E2oLcokd"| grep "$target" |cut -f1 | grep "$target"| awk '{print $2}'  > ultimatesubs/ubscraper.txt

echo "[+] Running SubDomainizer for subdomain enumeration."
python3 ~/tools/SubDomainizer/SubDomainizer.py -u http://$target -o  ultimatesubs/subdominizer.txt 

echo "[+] Running subdomains-scanner for subdomain enumeration."
subdomain-scanner -depth 3 -d "$target" -t 300 -f ~/go/src/github.com/fengdingbo/subdomain-scanner/dict/subnames_full.txt |awk '{print $2}' |grep "$target" |tr -d "{"> ultimatesubs/subdomain-scanner.txt

echo "[+] Running chaos for subdomain enumeration."
export CHAOS_KEY="a01b4a1eae3ec7ea5293318487e2aa83208c428103740e553ddde3bac8e412d1"
chaos -d "$target" -silent|grep "$target" > ultimatesubs/chaos.txt

echo "[+] Running assetfinder for subdomain enumeration."
assetfinder --subs-only "$target" > ultimatesubs/assetfinder.txt

echo "[+] Running delator for subdomain enumeration."
delator -d "$target" -s crt > ultimatesubs/delator.txt

echo "[+] Running vita for subdomain enumeration."
~/tools/vita-0.1.14-x86_64-unknown-linux-musl/vita -d "$target" -c 300 > ultimatesubs/vita.txt

echo "[+] Running subfinder for subdomain enumeration."
subfinder -silent -d "$target" -t 50 > ultimatesubs/subfinder.txt

echo "[+] Running nmap dns-bruteforcing for subdomain enumeration."
nmap --script dns-brute "$target" | grep "$target" |tail -n +3 | cut -c 7- | cut -f1 -d ' '| uniq > ultimatesubs/nmap.txt

echo "[+] Running dnscan for subdomain enumeration."
 python3 ~/tools/dnscan/dnscan.py -t 32 -d "$target" -w ~/tools/dnscan/subdomains-10000.txt  -n -t 50  | egrep -o  "\S+$target" > ultimatesubs/dnscan.txt

echo "[+] Starting github-subdomain.py for subdomain enumeration."
python3 ~/tools/github-search/github-subdomains.py -t e5ee760a9e3e84b42282bf7d744dca095b7f9c34  -d "$target" > ultimatesubs/github-subdomains.txt

echo "[+] Starting crobat for subdomain enumeration."
crobat -s "$target" > ultimatesubs/crobat.txt

cat ultimatesubs/* | sort -u > ultimatesubs/subs.txt

echo "[+] Getting DNS SOA records."
dnsx -t 400 -silent -l ultimatesubs/subs.txt -soa -o ultimatesubs/soa.txt

echo "[+] Getting DNS MX records."
dnsx -t 400 -silent -l ultimatesubs/subs.txt -mx -o ultimatesubs/mx.txt

echo "[+] Getting DNS TXT records."
dnsx -t 400 -silent -l ultimatesubs/subs.txt -txt -o ultimatesubs/txt.txt

echo "[+] Getting DNS PTR records."
dnsx -t 400 -silent -l ultimatesubs/subs.txt -ptr -o ultimatesubs/ptr.txt

echo "[+] Getting DNS NS records."
dnsx -t 400 -silent -l ultimatesubs/subs.txt -ns -o ultimatesubs/ns.txt

echo "[+] Getting DNS A records."
dnsx -t 400 -silent -l ultimatesubs/subs.txt -a -o ultimatesubs/a.txt

echo "[+] Getting DNS AAAA records."
dnsx -t 400 -silent -l ultimatesubs/subs.txt -aaaa -o ultimatesubs/aaaa.txt

echo "[+] Getting DNS CNAME records."
dnsx -t 400 -silent -l ultimatesubs/subs.txt -cname -o ultimatesubs/cname.txt

cat ultimatesubs/* | sort -u > ultimatesubs/subs2.txt

echo "[+] Starting shuffle dns to enumerate valid subdomains."
shuffledns -d $target -silent -w ~/tools/best-dns-wordlist.txt -r ~/tools/resolvers.txt -o ultimatesubs/shuffledns.txt

echo "[+] Starting ffuf for vhost bruteforce."
gobuster vhost -q -u verizon.com -w ../all.txt -t 50 |grep "Status: 200" > ultimatesubs/vhost.txt

cat ultimatesubs/* | sort -u > ultimatesubs/allsubdomains.txt

echo "[+] Starting httpx for alive subdomains check."
cat ultimatesubs/allsubdomains.txt |httpx -threads 300 -silent -o ultimatesubs/httpx.txt

echo "[+] Starting favfreak."
cat ultimatesubs/httpx.txt |python3 ~/tools/FavFreak/favfreak.py |sed -n -e '/Detection/,/Summary/ p'  |grep "$target" > ultimatesubs/favfreak.txt

echo "[+] Checking for subdomains redirection."
a="ultimatesubs/httpx.txt"
cat $a | while read a; do
    if curl -Is $a | grep "Location"; then
        echo "$a redirects to `curl -Is $a | grep "Location"`" > ultimatesubs/redirections.txt
    fi
done

cat ultimatesubs/httpx.txt ultimatesubs/favfreak.txt | cut -d "/" -f3 > subdomains.txt
