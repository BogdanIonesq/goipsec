# Testing VM Setup
Architecture:
```
Laptop(192.168.2.237) ---> Local/Middle Gateway(192.168.2.107) ---> Remote Gateway(192.168.2.221)
```

Add route to remote gateway through the middle gateway:
```
$ sudo ip route add 192.168.2.221/32 via 192.168.2.107
```

Add iptables rules to middle gateway to not send ICMP Redirect packets
```
$ sudo iptables -t mangle -A POSTROUTING -p icmp --icmp-type redirect -j DROP
```

and to not automatically forward packets
```
$ sudo iptables -I FORWARD -d 192.168.2.221 -j DROP
```