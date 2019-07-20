FROM golang:1.12-alpine

RUN apk update && apk add tcpdump git

RUN go get github.com/google/gopacket

WORKDIR /ipsec

CMD [ "sleep", "infinity" ]