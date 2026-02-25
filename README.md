Soon ...

sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -d 172.16.241.134 -j DROP

nc -l -p 80

tcp.port == 80 and ip.addr == 172.16.241.134

