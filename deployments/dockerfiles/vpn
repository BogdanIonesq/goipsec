FROM golang:1.12-alpine

RUN apk update && apk add tcpdump git iptables netcat-openbsd gcc libc-dev libpcap-dev

RUN go get github.com/google/gopacket

WORKDIR /ipsec

CMD [ "sleep", "2147483647" ]