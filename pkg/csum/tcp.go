package csum

import (
	"github.com/google/gopacket/layers"
)

func TCPIPv4(srcaddr, dstaddr, tcpdata []byte) uint16 {
	var csum uint32
	var tcplen uint32 = uint32(len(tcpdata))

	// clear checksum bytes
	tcpdata[16] = 0
	tcpdata[17] = 0

	csum += uint32(srcaddr[0]) << 8
	csum += uint32(srcaddr[1])
	csum += uint32(srcaddr[2]) << 8
	csum += uint32(srcaddr[3])

	csum += uint32(dstaddr[0]) << 8
	csum += uint32(dstaddr[1])
	csum += uint32(dstaddr[2]) << 8
	csum += uint32(dstaddr[3])

	csum += uint32(layers.IPProtocolTCP)
	csum += tcplen

	end := len(tcpdata) - 1

	for i := 0; i < end; i += 2 {
		csum += uint32(tcpdata[i]) << 8
		csum += uint32(tcpdata[i+1])
	}

	if len(tcpdata)%2 == 1 {
		csum += uint32(tcpdata[end]) << 8
	}

	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)

}

func TCPIPv6(srcaddr, dstaddr, tcpdata []byte) uint16 {
	var csum uint32 = 0
	var tcplen uint32 = uint32(len(tcpdata))

	// clear checksum bytes
	tcpdata[16] = 0
	tcpdata[17] = 0

	for i := 0; i <= 14; i += 2 {
		csum += uint32(srcaddr[i]) << 8
		csum += uint32(srcaddr[i+1])
	}

	for i := 0; i <= 14; i += 2 {
		csum += uint32(dstaddr[i]) << 8
		csum += uint32(dstaddr[i+1])
	}

	csum += tcplen
	csum += uint32(layers.IPProtocolTCP)

	end := len(tcpdata) - 1

	for i := 0; i < end; i += 2 {
		csum += uint32(tcpdata[i]) << 8
		csum += uint32(tcpdata[i+1])
	}

	if len(tcpdata)%2 == 1 {
		csum += uint32(tcpdata[end]) << 8
	}

	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)
}
