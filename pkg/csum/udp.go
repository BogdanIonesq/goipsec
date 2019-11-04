package csum

import "github.com/google/gopacket/layers"

func UDPIPv4(srcaddr, dstaddr, udpdata []byte) uint16 {
	var csum uint32
	var udplen uint32 = uint32(len(udpdata))

	// clear checksum bytes
	udpdata[6] = 0
	udpdata[7] = 0

	csum += uint32(srcaddr[0]) << 8
	csum += uint32(srcaddr[1])
	csum += uint32(srcaddr[2]) << 8
	csum += uint32(srcaddr[3])

	csum += uint32(dstaddr[0]) << 8
	csum += uint32(dstaddr[1])
	csum += uint32(dstaddr[2]) << 8
	csum += uint32(dstaddr[3])

	csum += uint32(layers.IPProtocolUDP)
	csum += udplen

	end := len(udpdata) - 1

	for i := 0; i < end; i += 2 {
		csum += uint32(udpdata[i]) << 8
		csum += uint32(udpdata[i+1])
	}

	if len(udpdata)%2 == 1 {
		csum += uint32(udpdata[end]) << 8
	}

	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)

}

func UDPIPv6(srcaddr, dstaddr, udpdata []byte) uint16 {
	var csum uint32
	var udplen uint32 = uint32(len(udpdata))

	// clear checksum bytes
	udpdata[6] = 0
	udpdata[7] = 0

	for i := 0; i <= 14; i += 2 {
		csum += uint32(srcaddr[i]) << 8
		csum += uint32(srcaddr[i+1])
	}

	for i := 0; i <= 14; i += 2 {
		csum += uint32(dstaddr[i]) << 8
		csum += uint32(dstaddr[i+1])
	}

	csum += udplen
	csum += uint32(layers.IPProtocolUDP)

	end := len(udpdata) - 1

	for i := 0; i < end; i += 2 {
		csum += uint32(udpdata[i]) << 8
		csum += uint32(udpdata[i+1])
	}

	if len(tcpdata)%2 == 1 {
		csum += uint32(udpdata[end]) << 8
	}

	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)
}
