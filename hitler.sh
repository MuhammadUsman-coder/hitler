#!/bin/bash

target=$1;
source ~/.bash_profile
echo "[+] Checking tools required for subdomain enumeration."

# for i in {"./bugbounty/$target/recon/subdomain/"};do
#         mkdir -p $i;
# done

mkdir -p ./bugbounty/$target/detail-recon/subdomains/
mkdir -p ./bugbounty/$target/summary-recon/
mkdir -p ./bugbounty/$target/scanning/nuclie/
mkdir -p ./bugbounty/$target/detail-recon/spidering/
mkdir -p ./bugbounty/$target/summary-recon/links/

echo "[+] Starting subdomain enumeration."

echo "[+] Starting sublist3r for subdomain enumeration."
python3 ~/tools/Sublist3r/sublist3r.py -d "$target"  > ./bugbounty/$target/detail-recon/subdomains/sublist3r.txt

echo "[+] Starting amass for subdomain enumeration."
~/tools/amass_linux_amd64/amass enum -passive -d "$target" > ./bugbounty/$target/detail-recon/subdomains/amass.txt

echo "[+] Starting find-domain for subdomain enumeration."
~/tools/findomain-linux  -t "$target" -u ./bugbounty/$target/detail-recon/subdomains/findomain.txt

echo "[+] Running subscraper for subdomain enumeration."
subscraper -t 100 "$target" --censys-api "29c6e13b-bdd2-46d8-b6b7-1f679b4ee70d" --censys-secret "CfEDWOxM2OLR8CYzfNnK0V46E2oLcokd"| grep "$target" |cut -f1 | grep "$target"| awk '{print $2}'  > ./bugbounty/$target/detail-recon/subdomains/subscraper.txt

echo "[+] Running SubDomainizer for subdomain enumeration."
python3 ~/tools/SubDomainizer/SubDomainizer.py -u http://$target -o  ./bugbounty/$target/detail-recon/subdomains/subdominizer.txt > /dev/null 2>&1

echo "[+] Running subdomains-scanner for subdomain enumeration."
subdomain-scanner -depth 3 -d "$target" -t 300 -f ~/go/src/github.com/fengdingbo/subdomain-scanner/dict/subnames_full.txt -o ./bugbounty/$target/detail-recon/subdomains/subdomain-scanner.txt 

echo "[+] Running chaos for subdomain enumeration."
export CHAOS_KEY="a01b4a1eae3ec7ea5293318487e2aa83208c428103740e553ddde3bac8e412d1"
chaos -d "$target" -silent|grep "$target" > ./bugbounty/$target/detail-recon/subdomains/chaos.txt

echo "[+] Running assetfinder for subdomain enumeration."
assetfinder --subs-only "$target" > ./bugbounty/$target/detail-recon/subdomains/assetfinder.txt

echo "[+] Running delator for subdomain enumeration."
delator -d "$target" -s crt > ./bugbounty/$target/detail-recon/subdomains/delator.txt

echo "[+] Running vita for subdomain enumeration."
~/tools/vita-0.1.14-x86_64-unknown-linux-musl/vita -d "$target" -c 300 > ./bugbounty/$target/detail-recon/subdomains/vita.txt

echo "[+] Running subfinder for subdomain enumeration."
subfinder -silent -d "$target" -t 50 > ./bugbounty/$target/detail-recon/subdomains/subfinder.txt

echo "[+] Running nmap dns-bruteforcing for subdomain enumeration."
nmap --script dns-brute "$target" | grep "$target" |tail -n +3 | cut -c 7- | cut -f1 -d ' '| uniq > ./bugbounty/$target/detail-recon/subdomains/nmap.txt

echo "[+] Running dnscan for subdomain enumeration."
python3 ~/tools/dnscan/dnscan.py -t 32 -d "$target" -w ~/tools/dnscan/subdomains-10000.txt  -n -t 50  | grep "$target" | tail -n +3 | cut -f3 -d ' ' > ./bugbounty/$target/detail-recon/subdomains/dnscan.txt

# echo "[+] Running rush with seclist for subdomain enumeration."
# rush -j200 -i ~/tools/best-dns-wordlist.txt  ' curl -s -L "https://dns.google.com/resolve?name={}."'"$target.com"'"&type=A&cd=true" | sed "s#\"#\n# g;s# #\n#g" | grep "'"$target"'"' | sed ' s#\.$##g' |httpx| anew ./bugbounty/$target/detail-recon/subdomain/rush.txt

echo "[+] Starting github-subdomain.py for subdomain enumeration."
python3 ~/tools/github-search/github-subdomains.py -t e5ee760a9e3e84b42282bf7d744dca095b7f9c34  -d "$target" > ./bugbounty/$target/detail-recon/subdomains/github-subdomains.txt

cat ./bugbounty/$target/detail-recon/subdomains/* | sort -u > ./bugbounty/$target/detail-recon/subdomains/subs.txt

echo "[+] Starting crobat for subdomain enumeration."
crobat -s "$target" > ./bugbounty/$target/detail-recon/subdomains/crobat.txt

echo "[+] Getting DNS SOA records."
dnsx -t 400 -silent -l ./bugbounty/$target/detail-recon/subdomains/subs.txt -soa -o ./bugbounty/$target/detail-recon/subdomains/soa.txt

echo "[+] Getting DNS MX records."
dnsx -t 400 -silent -l ./bugbounty/$target/detail-recon/subdomains/subs.txt -mx -o ./bugbounty/$target/detail-recon/subdomains/mx.txt

echo "[+] Getting DNS TXT records."
dnsx -t 400 -silent -l ./bugbounty/$target/detail-recon/subdomains/subs.txt -txt -o ./bugbounty/$target/detail-recon/subdomains/txt.txt

echo "[+] Getting DNS PTR records."
dnsx -t 400 -silent -l ./bugbounty/$target/detail-recon/subdomains/subs.txt -ptr -o ./bugbounty/$target/detail-recon/subdomains/ptr.txt

echo "[+] Getting DNS NS records."
dnsx -t 400 -silent -l ./bugbounty/$target/detail-recon/subdomains/subs.txt -ns -o ./bugbounty/$target/detail-recon/subdomains/ns.txt

echo "[+] Getting DNS A records."
dnsx -t 400 -silent -l ./bugbounty/$target/detail-recon/subdomains/subs.txt -a -o ./bugbounty/$target/detail-recon/subdomains/a.txt

echo "[+] Getting DNS AAAA records."
dnsx -t 400 -silent -l ./bugbounty/$target/detail-recon/subdomains/subs.txt -aaaa -o ./bugbounty/$target/detail-recon/subdomains/aaaa.txt

echo "[+] Getting DNS CNAME records."
dnsx -t 400 -silent -l ./bugbounty/$target/detail-recon/subdomains/subs.txt -cname -o ./bugbounty/$target/detail-recon/subdomains/cname.txt

cat ./bugbounty/$target/detail-recon/subdomains/* | sort -u > ./bugbounty/$target/detail-recon/subdomains/subs2.txt

echo "[+] Starting shuffle dns to enumerate valid subdomains."
shuffledns -silent -list ./bugbounty/$target/detail-recon/subdomains/subs2.txt  -r ~/tools/resolvers.txt -o ./bugbounty/$target/detail-recon/subdomains/shuffledns.txt

echo "[+] Starting ffuf for vhost bruteforce."
ffuf -w ~/tools/v-host.txt -u http://"$target"/ -H "Host:http://FUZZ.$target" -k -mc 200,204,301,302,307,401,500,404 -t 50 -or ./bugbounty/$target/detail-recon/subdomains/vhost.txt

cat ./bugbounty/$target/detail-recon/subdomains/* | sort -u > ./bugbounty/$target/detail-recon/subdomains/allsubdomains.txt

echo "[+] Starting subjack for subdomain takeover."
subjack -t 50 -w ./bugbounty/$target/detail-recon/subdomains/allsubdomains.txt -a -ssl -t 50 -v -c ~/go/src/github.com/haccer/subjack/fingerprints.json -o ./bugbounty/$target/scanning/subjack.txt grep -v "Not Vulnerable" 

echo "[+] Starting nuclei for subdomain takeover."
nuclei -c 50 -silent -l ./bugbounty/$target/detail-recon/subdomains/allsubdomains.txt -t ~/tools/nuclei-templates/subdomain-takeover -c 50 -o ./bugbounty/$target/scanning/nuclie/nuclei-takeover.txt

echo "[+] Starting httpx for alive subdomains check."
cat ./bugbounty/$target/detail-recon/subdomains/allsubdomains.txt |httpx -threads 300 -silent -o ./bugbounty/$target/summary-recon/httpx.txt

echo "[+] Checking for subdomains redirection."
a="./bugbounty/$target/summary-recon/httpx.txt"
cat $a | while read a; do
    if curl -Is $a | grep "Location"; then
        echo "$a redirects to `curl -Is $a | grep "Location"`" > ./bugbounty/$target/summary-recon/redirections.txt
    fi
done

cat ./bugbounty/$target/summary-recon/httpx.txt | cut -d "/" -f3 > ./bugbounty/$target/summary-recon/subdomains.txt

links="./bugbounty/$target/summary-recon/httpx.txt"
echo "[+] Starting nuclie to check for used technologies."
nuclei -silent -l $links -t ~/tools/nuclei-templates/technologies/ -c 50 -o ./bugbounty/$target/scanning/nuclie/technologies.txt

echo "[+] Starting nuclie with generic-detections template."
nuclei -silent -l $links -t ~/tools/nuclei-templates/generic-detections/ -c 50 -o ./bugbounty/$target/scanning/nuclie/generic-detections.txt

echo "[+] Starting nuclie with CVES template."
nuclei -silent -l $links -t ~/tools/nuclei-templates/cves/ -c 50 -o ./bugbounty/$target/scanning/nuclie/cves.txt

echo "[+] Starting nuclie with default-credentials template."
nuclei -silent -l $links -t ~/tools/nuclei-templates/default-credentials/ -c 50 -o ./bugbounty/$target/scanning/nuclie/default-credentials.txt

echo "[+] Starting nuclie with dns template."
nuclei -silent -l $links -t ~/tools/nuclei-templates/dns/ -c 50 -o ./bugbounty/$target/scanning/nuclie/dns.txt

echo "[+] Starting nuclie with files template."
nuclei -silent -l $links -t ~/tools/nuclei-templates/files/ -c 50 -o ./bugbounty/$target/scanning/nuclie/files.txt

echo "[+] Starting nuclie with panels template."
nuclei -silent -l $links -t ~/tools/nuclei-templates/panels/ -c 50 -o ./bugbounty/$target/scanning/nuclie/panels.txt

echo "[+] Starting nuclie with security-misconfiguration template."
nuclei -silent -l $links -t ~/tools/nuclei-templates/security-misconfiguration/ -c 50 -o ./bugbounty/$target/scanning/nuclie/security-misconfiguration.txt

echo "[+] Starting nuclie with tokens template."
nuclei -silent -l $links -t ~/tools/nuclei-templates/tokens/ -c 50 -o ./bugbounty/$target/scanning/nuclie/tokens.txt

echo "[+] Starting nuclie with vulnerabilities template."
nuclei -silent -l $links -t ~/tools/nuclei-templates/vulnerabilities/ -c 50 -o ./bugbounty/$target/scanning/nuclie/vulnerabilities.txt

echo "[+] Starting webanalyze for technologies enumeration."
webanalyze -apps ~/tools/apps.json -hosts ./bugbounty/$target/summary-recon/subdomains.txt -crawl 1 -silent -worker 20 > ./bugbounty/$target/summary-recon/webanalyze.txt

echo "[+] Starting GAU for link enumeration."
cat $links | sed 's/https\?:\/\///' | gau > ./bugbounty/$target/detail-recon/spidering/getallurls.txt

echo "[+] Starting unfurl for param mining."
cat ./bugbounty/$target/detail-recon/spidering/getallurls.txt | sort -u | unfurl --unique keys > ./bugbounty/$target/summary-recon/paramlist.txt

echo "[+] Extracting js files."
cat ./bugbounty/$target/detail-recon/spidering/getallurls.txt | sort -u | grep -P "\w+\.js(\?|$)" | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u > ./bugbounty/$target/summary-recon/links/jsurls.txt

echo "[+] Extracting php files."
cat ./bugbounty/$target/detail-recon/spidering/getallurls.txt | sort -u | grep -P "\w+\.php(\?|$)" | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u  > ./bugbounty/$target/summary-recon/links/phpurls.txt

echo "[+] Extracting aspx files."
cat ./bugbounty/$target/detail-recon/spidering/getallurls.txt | sort -u | grep -P "\w+\.aspx(\?|$) | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u " > ./bugbounty/$target/summary-recon/links/aspxurls.txt

echo "[+] Extracting jsp files."
cat ./bugbounty/$target/detail-recon/spidering/getallurls.txt | sort -u | grep -P "\w+\.jsp(\?|$) | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u " > ./bugbounty/$target/summary-recon/links/jspurls.txt

echo "[+] Starting CorsMe for cors misconfiguration detection."
cat $links | CorsMe -t 70 > ./bugbounty/$target/scanning/corsme.txt

echo "[+] Starting crlfuzz."
crlfuzz -l ./bugbounty/$target/detail-recon/spidering/getallurls.txt -s > ./bugbounty/$target/scanning/crlfuzz.txt


echo "[+] Starting metabigor"
echo 'shuftipro.com' | metabigor net --org -v

echo "[+] Extracting asn numbers"
curl -s https://www.ultratools.com/tools/asnInfoResult?domainName=cisco|egrep  -o 'AS[0-9]+'


echo "[+] Getting ips from view-dns"
curl "https://api.viewdns.info/iphistory/?domain=shuftipro.com&apikey=3191026f942e0bd934218ca68bd408a13fdf5337&output=xml"|grep -oE '[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}'

echo "[+] Checking asn numbers found"
https://ipinfo.io/asn123123


echo "[+] Starting FavFreak"
cat urls.txt | python3 favfreak.py 

echo "[+] Starting subrute"
./subbrute.py all.txt corp.google.com |massdns -r resolvers.txt -t A -a -o -w gcorp.txt -"
