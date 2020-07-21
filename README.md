# GoIPsec

GoIPsec represents my bachelor's thesis submitted to the Faculty of Mathematics and Computer Science &mdash; University of Bucharest.

GoIPsec is a VPN application implemented in the Go programming language, featuring IPsec ESP encapsulation of network packets. Therefore, GoIPsec is able to maintain a bidirectional secure tunnel between two devices, which could be used to bypass traffic monitoring techniques, IP address-based geo-blocking and many more.

## Sounds cool! Where do I find stuff?

The actual **thesis paper** (along with its LaTeX template) can be found in the [docs](https://github.com/BogdanIonesq/goipsec/tree/master/docs) directory. It takes a deep dive into the risks of using public networks (such as the Internet) and how VPNs might help us mitigate them, while also analyzing IPsec, a very complex and flexible network protocol suite meant to address a plethora of security needs over networks.

Most of the **code** is located in the [pkg](https://github.com/BogdanIonesq/goipsec/tree/master/pkg) directory. The `gateway` package does the most heavy lifting, while `csum` and `glog` provide checksum calculations and logging.

The **Docker setup**, including Docker Compose platforms and container dockerfiles, is available in [deployments](https://github.com/BogdanIonesq/goipsec/tree/master/docs).

## Setup

To test GoIPsec, simply clone this repository in your `$GOPATH`'s `src` directory, or just run
```
$ go get github.com/BogdanIonesq/goipsec
```

After this, assuming you already have [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/) installed, run one of the YAML configuration files available in `deployments`:
```
$ cd $GOPATH/src/github.com/BogdanIonesq/goipsec/deployments
$ docker-compose -f goipsec-udp.yml up --abort-on-container-exit
```

The `goipsec-udp.yml` platform sends an UDP message from the client to simple netcat UDP server, while the `goipsec-tcp.yml` example completes a TCP handshake with an nginx instance, followed by a GET request and termination of the connection.

To make sure that GoIPsec actually secures (with regard to confidentiality and integrity) the data between the two VPN gateways, the network traffic for each container is written to `logs/udp` or `logs/tcp`, respectively.

## Details
A GoIPsec VPN gateway relies on [libpcap](https://www.tcpdump.org/) bindings through the [gopacket](https://github.com/google/gopacket) library to capture the client's network packets (IPv4 or IPv6 datagrams) directly from the kernel. 

Once such a packet is received, [ESP](https://tools.ietf.org/html/rfc4303) encapsulation is applied, with encryption and integrity provided by AES-256 in CBC mode and HMAC-SHA512/256, respectively. Further UDP encapsulation is implemented for NAT traversal.

The server-side GoIPsec gateway is responsible with checking the integrity, decrypting packets, changing the IP source address and forwarding the packets to their actual destination.
