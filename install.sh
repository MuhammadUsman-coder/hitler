
#!/bin/bash

echo "[+] All tools will be installed in ~/tools."
mkdir ~/tools
cd ~/tools
sudo apt-get -y update
sudo apt install -y sudo git python python3 python3-pip curl unzip wget

if ! [ -x "$(command -v go)" ];then 
  echo "[+] Go not installed";
  echo "[+] Installing Golang"
  wget https://golang.org/dl/go1.15.6.linux-amd64.tar.gz
  sudo tar -xf go1.15.6.linux-amd64.tar.gz
  sudo mv go /usr/local
  export GOROOT=/usr/local/go
  export GOPATH=$HOME/go
  export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
  echo 'export GOROOT=/usr/local/go' >> ~/.bash_profile
  echo 'export GOPATH=$HOME/go'    >> ~/.bash_profile            
  echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> ~/.bash_profile    
  source ~/.bash_profile
fi


# if ! [ -d ~/go ];then
#   echo "go directory not found in home directory."
# fi
echo "[+] Installing amass."
wget https://github.com/OWASP/Amass/releases/download/v3.10.5/amass_linux_amd64.zip
unzip amass*

echo "[+] Installing Sublist3r"
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r*
pip install -r requirements.txt
cd ~/tools/
sudo pip3 install requests
sudo pip3 install dnspython
sudo pip3 install argparse
echo "[+] Done"


echo "[+] downloading v-Host wordlist."
curl https://raw.githubusercontent.com/codingo/VHostScan/master/VHostScan/wordlists/virtual-host-scanning.txt > v-host.txt

# echo "[+] Installing GO."
# sudo apt-get install golang -y
# echo "export PATH=$PATH:~/go/bin" >> ~/.profile
# source ~/.profile

echo "[+] Installing findSubdomains."
wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux
chmod +x findomain-linux
echo "[+] Done."

echo "[+] Installing subscraper."
git clone https://github.com/m8r0wn/subscraper  > /dev/null 2>&1
pip3 -q install -r subscraper/requirements.txt  > /dev/null 2>&1
cd subscraper/
python3 setup.py install > /dev/null 2>&1
cd ..;
echo "[+] Done."

echo "[+] Installing SubDomainizer."
git clone  https://github.com/nsonaniya2010/SubDomainizer.git  > /dev/null 2>&1
pip3 -q install -r SubDomainizer/requirements.txt > /dev/null 2>&1
echo "[+] Done"

echo "[+] Installing subdomains-scanner."
go get github.com/miekg/dns > /dev/null 2>&1
go get github.com/hashicorp/go-multierror > /dev/null 2>&1
go get github.com/fengdingbo/subdomain-scanner > /dev/null 2>&1
make -C ~/go/src/github.com/fengdingbo/subdomain-scanner/ 
echo "[+] Done"    
 
echo "[+] Installing assetfinder."
go get -u github.com/tomnomnom/assetfinder
echo "[+] Done."

echo "[+] Installing chaos."
GO111MODULE=on go get -u github.com/projectdiscovery/chaos-client/cmd/chaos
echo "[+] Done."

echo "[+] Installing delator."
go get github.com/netevert/delator
go build ~/go/src/github.com/netevert/delator/delator.go
echo "[+] Done."

echo "[+] Installing rush."
go get -u github.com/shenwei356/rush/
echo "[+] Done."
 
echo "[+] Installing anew."
go get -u github.com/tomnomnom/anew
echo "[+] Done."

echo "[+] Installing vita."
wget -q https://github.com/junnlikestea/vita/releases/download/0.1.14/vita-0.1.14-x86_64-unknown-linux-musl.tar.gz
tar -xf vita-0.1.14-x86_64-unknown-linux-musl.tar.gz
echo "[+] Done."

echo "[+] Installing subfinder."
GO111MODULE=on go get -u -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder
echo "[+] Done."

echo "[+] Installing dnsx."
GO111MODULE=on go get -u -v github.com/projectdiscovery/dnsx/cmd/dnsx
echo "[+] Done."

echo "[+] Installing shuffledns"
GO111MODULE=on go get -u -v github.com/projectdiscovery/shuffledns/cmd/shuffledns
echo "[+] Done."

echo "[+] Downloading resolvers.txt for shuffledns."
wget -q https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt
echo "[+] Done."

echo "[+] Downloading ffuf."
go get -u github.com/ffuf/ffuf
echo "[+] Done."

echo "[+] Installing subjack."
go get github.com/haccer/subjack
echo "[+] Done."

echo "[+] Installing nuclei."
GO111MODULE=on go get -u -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
git clone https://github.com/projectdiscovery/nuclei-templates.git
echo "[+] Done."

echo "[+] Installing massdns."
git clone https://github.com/blechschmidt/massdns.git 
make -C massdns/
cp massdns/bin/massdns /usr/bin/
echo "[+] Done."

echo "[+] Installing nmap."
sudo apt install nmap -y
echo "[+] Done."

echo "[+] Installing dnscan."
git  clone https://github.com/rbsec/dnscan.git  > /dev/null 2>&1
pip3 -q install -r dnscan/requirements.txt > /dev/null 2>&1
echo "[+] Done"

echo "[+] Installing httpx"
GO111MODULE=on go get -u github.com/projectdiscovery/httpx/cmd/httpx > /dev/null 2>&1
echo "[+] Done."

echo "[+] Downloading wordlist for dns-bruteforcing."
wget -q https://s3.amazonaws.com/assetnote-wordlists/data/manual/best-dns-wordlist.txt
echo "[+] Done."

echo "[+] Installing webanalyze"
go get -u github.com/rverton/webanalyze/cmd/webanalyze
webanalyze -update

echo "[+] Installing unfurl."
go get -u github.com/tomnomnom/unfurl

echo "[+] Installing github-subdomain search."
git clone https://github.com/gwen001/github-search.git
pip3 install -r github-search/requirements2.txt
pip3 install -r github-search/requirements2.txt

echo "[+] Installing crobat for subdomain enumeration."
go get -u github.com/cgboal/sonarsearch/crobat

echo "[+] Install crlfuzz"
GO111MODULE=on go get -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz

echo "[+] Installing GAU."
GO111MODULE=on go get -u -v github.com/lc/gau

echo "[+] Installing corsme"
go get -u -v github.com/shivangx01b/CorsMe

echo "[+] Installing waybackurls"
go get github.com/tomnomnom/waybackurls

echo "[+] Installing metabigor"
go get -u github.com/j3ssie/metabigor

wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt install ./google-chrome-stable_current_amd64.deb

echo "[+] Insatlling asnlookup"
git clone https://github.com/yassineaboukir/Asnlookup && cd Asnlookup
pip3 install -r requirements.txt 
cd ..

echo "Insatlling FavFrek."
git clone https://github.com/devanshbatham/FavFreak
cd FavFreak
virtualenv -p python3 env
source env/bin/activate
python3 -m pip install mmh3



echo "[+] Please configure subfinder keys by running the following lines in script."
# echo "[+]Adding api keys in subfinder config file."
# subfinder --help > /dev/null
# touch ~/.config/subfinder/config.yaml
# line=$(cat -n ~/.config/subfinder/config.yaml|grep binaryedge: |awk '{print $1}')
# echo $line
# sed -i "${line},\$d" ~/.config/subfinder/config.yaml 
# echo """
# binaryedge:
#   - b63cc93b-5b72-426d-8141-7a22d4927305
# censys:
#   - 29c6e13b-bdd2-46d8-b6b7-1f679b4ee70d:CfEDWOxM2OLR8CYzfNnK0V46E2oLcokd
# certspotter:
#   - 32919_sMCauuiKvIWuWRmdGZll
# chaos:
#   - a01b4a1eae3ec7ea5293318487e2aa83208c428103740e553ddde3bac8e412d1
# dnsdb:
#   - 2f4a5083f44ce5702a7c86f770ed157f3eb98d519ea46ab4c5bed7239e8c660d
# github:
#   - deb5b594aa1ff575f8117f42dd5d3e8b16379473
# intelx:
#   - 57cd7cac-0dfe-4254-ab3e-524a690c3867
# passivetotal:
#   - 6b12dc7b8ddb20b42f59a0398d5fe31ba4beb247464602f9ce50d4de71ff8bc7
# recon: []
# robtex:
#   - 51BHtnjT9TfRONnE1ud8
# securitytrails:
#   - UAwTto0HEx60SUpX6lS6Qd8gfvLKjwbk
# shodan:
#   - jQIqdSSf8czWjZcF1EHzfPtyLQGfxpOE
# spyse:
#   - b60e4d57-f03a-4820-a8c6-49e94a257e13
# threatbook: []
# urlscan:
#   - 7c858bcf-d91b-478e-bb3e-518420fcbf19
# virustotal:
#   - 535864afe283421ea46b62ad6c2174a0d1cf7dd850a2ce38d02cb9136f24895e
# zoomeye:
#   - 26382A3A-6162-c2693-6631-dc25d62ff6f
# subfinder-version: 2.4.5
# """ >> ~/.config/subfinder/config.yaml
