#!/bin/bash
ip="$1"
 
function scan(){
   nmap -T4 -Pn -p$i-$j $ip|grep -i 'open' >> $ip.nmap &   
}
 
for (( i=1;i<=65000;i=i+5000 ));do
   j=$((i+5000))
   scan;
done
