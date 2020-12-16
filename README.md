# TCPTraceroute
In this project, we use raw TCP socket to perform the traceroute rather than using the UDP socket or ICMP socket. we formulate and send the 'sniff' raw TCP socket with ttl incremented, and detect the responding ICMP messages. Once the raw TCP socket reaches the destination with ttl larger than 0, we will receive the corresponding TCP message. each raw TCP socket will be sent three times.

the usage of the program is,
```shell
sudo Traceroute IP address/host name port
```
for example,
```shell
sudo Traceroute www.google.com 80
```

note that program requires sudo authority to create the raw socket.


