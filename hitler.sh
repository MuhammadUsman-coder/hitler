#!/bin/bash

target=$1;

echo "[+] Checking tools required for subdomain enumeration."
echo "[+] Making directory to install tools, all tools that required repositories to be cloned will be made in ./bugbounty/tools"

# for i in {"./bugbounty/$target/recon/subdomain/"};do
#         mkdir -p $i;
# done

mkdir -p ./bugbounty/$target/recon/subdomain/
echo "[+] Starting subdomain enumeration."

echo "[+] Starting sublist3r for subdomain enumeration."
sublist3r -d "$target"  > ./bugbounty/$target/recon/subdomain/sublist3r.txt

echo "[+] Starting amass for subdomain enumeration."
amass enum -passive -d "$target" > ./bugbounty/$target/recon/subdomain/amass.txt

echo "[+] Starting find-domain for subdomain enumeration."
python3 ~/tools/findSubDomains/findSubDomains.py "$target" -t 200 > ./bugbounty/$target/recon/subdomain/findSubs.txt

echo "[+] Running subscraper for subdomain enumeration."
subscraper -t 100 "$target" --censys-api "29c6e13b-bdd2-46d8-b6b7-1f679b4ee70d" --censys-secret "CfEDWOxM2OLR8CYzfNnK0V46E2oLcokd"| grep "$target" |cut -f1 | grep "$target"| awk '{print $2}'  > ./bugbounty/$target/recon/subdomain/subscraper.txt

echo "[+] Running SubDomainizer for subdomain enumeration."
python3 ~/tools/SubDomainizer/SubDomainizer.py -u http://$target -o  ./bugbounty/$target/recon/subdomain/subdominizer.txt > /dev/null 2>&1

echo "[+] Running subdomains-scanner for subdomain enumeration."
subdomain-scanner -depth 3 -d $target -t 300 -f ~/go/src/github.com/fengdingbo/subdomain-scanner/dict/subnames_full.txt -o ./bugbounty/$target/recon/subdomain/subdomain-scanner.txt 

echo "[+] Running chaos for subdomain enumeration."
export CHAOS_KEY="a01b4a1eae3ec7ea5293318487e2aa83208c428103740e553ddde3bac8e412d1"
chaos -d $target -silent|grep $target > ./bugbounty/$target/recon/subdomain/chaos.txt

echo "[+] Running assetfinder for subdomain enumeration."
assetfinder --subs-only $target > ./bugbounty/$target/recon/subdomain/assetfinder.txt

echo "[+] Running delator for subdomain enumeration."
delator -d $target -s crt > ./bugbounty/$target/recon/subdomain/delator.txt

echo "[+] Running vita for subdomain enumeration."
~/tools/vita/vita-0.1.14-x86_64-unknown-linux-musl/vita -d $target -c 300 > ./bugbounty/$target/recon/subdomain/vita.txt

echo "[+] Running subfinder for subdomain enumeration."
subfinder -silent -d $target -t 50 > ./bugbounty/$target/recon/subdomain/subfinder.txt

echo "[+] Running nmap dns-bruteforcing for subdomain enumeration."
nmap --script dns-brute $target | grep $target |tail -n +3 | cut -c 7- | cut -f1 -d ' '| uniq > ./bugbounty/$target/recon/subdomain/nmap.txt

echo "[+] Running dnscan for subdomain enumeration."
python3 ~/tools/dnscan/dnscan.py -t 32 -d $target -w ./bugbounty/tools/dnscan/subdomains-10000.txt  -n -t 50  | grep .$target | tail -n +3 | cut -f3 -d ' ' > /dev/null 2>&1

#echo "[+] Running rush with seclist for subdomain enumeration."
#rush -j200 -i ./bugbounty/tools/best-dns-wordlist.txt  ' curl -s -L "https://dns.google.com/resolve?name={}."'"$target.com"'"&type=A&cd=true" | sed "s#\"#\n# g;s# #\n#g" | grep "'"$target"'"' | sed ' s#\.$##g' |httpx| anew ./bugbounty/$target/recon/subdomain/rush.txt
cat ./bugbounty/$target/recon/subdomain/* |sort -u > ./bugbounty/$target/recon/subdomain/subs.txt

echo "[+] Starting github-subdomain.py for subdomain enumeration."
pytho3 github-search/github-subdomains.py -t e5ee760a9e3e84b42282bf7d744dca095b7f9c34  -d "$target" > ./bugbounty/$target/recon/subdomain/github-subdomains.txt

echo "[+] Starting crobat for subdomain enumeration."
crobat -s "$target"

echo "[+] Getting DNS SOA records."
dnsx -t 400 -silent -l ./bugbounty/$target/recon/subdomain/subs.txt -soa -o ./bugbounty/$target/recon/subdomain/soa.txt

echo "[+] Getting DNS MX records."
dnsx -t 400 -silent -l ./bugbounty/$target/recon/subdomain/subs.txt -mx -o ./bugbounty/$target/recon/subdomain/mx.txt

echo "[+] Getting DNS TXT records."
dnsx -t 400 -silent -l ./bugbounty/$target/recon/subdomain/subs.txt -txt -o ./bugbounty/$target/recon/subdomain/txt.txt

echo "[+] Getting DNS PTR records."
dnsx -t 400 -silent -l ./bugbounty/$target/recon/subdomain/subs.txt -ptr -o ./bugbounty/$target/recon/subdomain/ptr.txt

echo "[+] Getting DNS NS records."
dnsx -t 400 -silent -l ./bugbounty/$target/recon/subdomain/subs.txt -ns -o ./bugbounty/$target/recon/subdomain/ns.txt

echo "[+] Getting DNS A records."
dnsx -t 400 -silent -l ./bugbounty/$target/recon/subdomain/subs.txt -a -o ./bugbounty/$target/recon/subdomain/a.txt

echo "[+] Getting DNS AAAA records."
dnsx -t 400 -silent -l ./bugbounty/$target/recon/subdomain/subs.txt -aaaa -o ./bugbounty/$target/recon/subdomain/aaaa.txt

echo "[+] Getting DNS CNAME records."
dnsx -t 400 -silent -l ./bugbounty/$target/recon/subdomain/subs.txt -cname -o ./bugbounty/$target/recon/subdomain/cname.txt

cat ./bugbounty/$target/recon/subdomain/* | sort -u > ./bugbounty/$target/recon/subdomain/final2_subs.txt

echo "[+] Starting shuffle dns to enumerate valid subdomains."
shuffledns -silent -list ./bugbounty/$target/recon/subdomain/final2_subs.txt  -r ~/tools/resolvers.txt -o ./bugbounty/$target/recon/subdomain/shuffledns.txt

#echo "[+] Starting ffuf for vhost bruteforce."
#ffuf -w wordlist -u http://"$target"/ -H "Host:http://FUZZ.$target" -k -mc 200,204,301,302,307,401,403,500,404 -t 50 -o ./bugbounty/$target/recon/subdomain/vhost.txt

cat ./bugbounty/$target/recon/subdomain/* | sort -u > ./bugbounty/$target/recon/subdomain/allsubdomains.txt

echo "[+] Starting subjack for subdomain takeover."
subjack -t 50 -w ./bugbounty/$target/recon/subdomain/allsubdomains.txt -a -ssl -t 50 -v -c ~/go/src/github.com/haccer/subjack/fingerprints.json -o ./bugbounty/$target/recon/subjack.txt grep -v "Not Vulnerable" 

echo "[+] Starting nuclei for subdomain takeover."
nuclei -c 50 -silent -l ./bugbounty/$target/recon/subdomain/allsubdomains.txt -t ~/tools/nuclei-templates/subdomain-takeover -c 50 -o ./bugbounty/$target/recon/nuclie/nuclei-takeover.txt

echo "[+] Starting httpx for alive subdomains check."
cat ./bugbounty/$target/recon/subdomain/allsubdomains.txt |httpx -threads 300 -silent -o ./bugbounty/$target/recon/subdomain/alive.txt

echo "[+] Checking for subdomains redirection."
a="./bugbounty/$target/recon/subdomain/alive.txt"
cat $a | while read a; do
    if curl -Is $a | grep "Location"; then
        echo "$a redirects to `curl -Is $a | grep "Location"`" > ./bugbounty/$target/recon/subdomain/redirections.txt
echo
    else
        echo "$a (-_-)"
echo
    fi
done

echo "[+] Starting nuclie to check for used technologies."
nuclei -silent -l $targets -t ~/tools/nuclie-templates/technologies/ -c 50 -o ./bugbounty/$target/recon/nuclie/technologies.txt

echo "[+] Starting nuclie with generic-detections template."
nuclei -silent -l alive.txt -t ~/tools/nuclie-templates/generic-detections/ -c 50 -o ./bugbounty/$target/recon/nuclie/generic-detections.txt

echo "[+] Starting nuclie with CVES template."
nuclei -silent -l alive.txt -t ~/tools/nuclie-templates/cves/ -c 50 -o ./bugbounty/$target/recon/nuclie/cves.txt

echo "[+] Starting nuclie with default-credentials template."
nuclei -silent -l alive.txt -t ~/tools/nuclie-templates/default-credentials/ -c 50 -o ./bugbounty/$target/recon/nuclie/default-credentials.txt

echo "[+] Starting nuclie with dns template."
nuclei -silent -l alive.txt -t ~/tools/nuclie-templates/dns/ -c 50 -o ./bugbounty/$target/recon/nuclie/dns.txt

echo "[+] Starting nuclie with files template."
nuclei -silent -l alive.txt -t ~/tools/nuclie-templates/files/ -c 50 -o ./bugbounty/$target/recon/nuclie/files.txt

echo "[+] Starting nuclie with panels template."
nuclei -silent -l alive.txt -t ~/tools/nuclie-templates/panels/ -c 50 -o ./bugbounty/$target/recon/nuclie/panels.txt

echo "[+] Starting nuclie with security-misconfiguration template."
nuclei -silent -l alive.txt -t ~/tools/nuclie-templates/security-misconfiguration/ -c 50 -o ./bugbounty/$target/recon/nuclie/security-misconfiguration.txt

echo "[+] Starting nuclie with tokens template."
nuclei -silent -l alive.txt -t ~/tools/nuclie-templates/tokens/ -c 50 -o ./bugbounty/$target/recon/nuclie/tokens.txt

echo "[+] Starting nuclie with vulnerabilities template."
nuclei -silent -l alive.txt -t ~/tools/nuclie-templates/vulnerabilities/ -c 50 -o ./bugbounty/$target/recon/nuclie/vulnerabilities.txt

echo "[+] Starting webanalyze for technologies enumeration."
webanalyze -host shuftipro.com -crawl 1 -silent -worker 20 > ./bugbounty/$target/recon/webanalyze.txt

echo "[+] Starting GAU for link enumeration."
cat alive.txt | sed 's/https\?:\/\///' | gau > ./bugbounty/$target/recon/getallurls.txt

echo "[+] Starting nuclie with generic-detections template."
cat ./bugbounty/$target/recon/getallurls.txt | sort -u | unfurl --unique keys > ./bugbounty/$target/recon/paramlist.txt

echo "[+] Starting nuclie with generic-detections template."
cat ./bugbounty/$target/recon/getallurls.txt | sort -u | grep -P "\w+\.js(\?|$)" | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u > jsurls.txt

echo "[+] Starting nuclie with generic-detections template."
cat ./bugbounty/$target/recon/getallurls.txt | sort -u | grep -P "\w+\.php(\?|$)" | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u  > phpurls.txt

echo "[+] Starting nuclie with generic-detections template."
cat ./bugbounty/$target/recon/getallurls.txt | sort -u | grep -P "\w+\.aspx(\?|$) | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u " > "$ARCHIVE"/aspxurls.txt

echo "[+] Starting nuclie with generic-detections template."
cat alive.txt | sort -u | grep -P "\w+\.jsp(\?|$) | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u " > jspurls.txt

echo "[+] Starting nuclie with generic-detections template."
echo -e "[$GREEN+$RESET] fetchArchive finished"

echo "[+] Starting nuclie with generic-detections template."
cat alive.txt | ./CorsMe -t 70

echo "[+] Starting nuclie with generic-detections template."
crlfuzz -l file.txt >> saved.txt



