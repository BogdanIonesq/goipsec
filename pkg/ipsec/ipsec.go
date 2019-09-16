package ipsec

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"goipsec/global"
	"goipsec/pkg/csums"
	"net"
	"sync/atomic"
)

var GatewaySeqCount uint32 = 0
var ServerSeqCount uint32 = 0

func EncryptPacket(packet gopacket.Packet, send chan gopacket.SerializeBuffer, outgoing bool) {
	var srcIP, dstIP net.IP
	var srcMAC, dstMAC net.HardwareAddr
	// ESP header and trailer components
	sequenceNumber := make([]byte, 4)
	padLength := []byte{0}
	nextHeader := []byte{4}

	if outgoing {
		atomic.AddUint32(&GatewaySeqCount, 1)
		binary.BigEndian.PutUint32(sequenceNumber, GatewaySeqCount)

		srcIP = net.ParseIP(global.VPNGatewayIPv6)
		dstIP = net.ParseIP(global.VPNServerIPv6)

		srcMAC, _ = net.ParseMAC(global.VPNGatewayMAC)
		dstMAC, _ = net.ParseMAC(global.VPNServerMAC)
	} else {
		atomic.AddUint32(&ServerSeqCount, 1)
		binary.BigEndian.PutUint32(sequenceNumber, ServerSeqCount)

		srcIP = net.ParseIP(global.VPNServerIPv6)
		dstIP = net.ParseIP(global.VPNGatewayIPv6)

		srcMAC, _ = net.ParseMAC(global.VPNServerMAC)
		dstMAC, _ = net.ParseMAC(global.VPNGatewayMAC)
	}

	encryptedPacket := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(encryptedPacket, gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv6,
		},
		&layers.IPv6{
			Version:      6,
			TrafficClass: 0,
			FlowLabel:    0,
			Length:       uint16(8 + len(packet.Data()[global.NetworkLayerStart:]) + 2),
			NextHeader:   layers.IPProtocolESP,
			HopLimit:     64,
			SrcIP:        srcIP,
			DstIP:        dstIP,
		},
		// SPI
		gopacket.Payload([]byte{1, 2, 3, 4}),
		// sequence number
		gopacket.Payload(sequenceNumber),
		// payload data
		gopacket.Payload(packet.Data()[global.NetworkLayerStart:]),
		// pad length
		gopacket.Payload(padLength),
		// next header
		gopacket.Payload(nextHeader),
	)

	if err != nil {
		fmt.Println("Packet creation error: ", err)
	} else {
		send <- encryptedPacket
	}
}

func DecryptPacket(packet gopacket.Packet, send chan gopacket.SerializeBuffer, outgoing bool) {
	var srcIP, dstIP net.IP
	var srcMAC, dstMAC net.HardwareAddr

	if outgoing {
		srcIP = net.ParseIP(global.VPNServerIPv6)
		dstIP = net.ParseIP(global.WebServerIPv6)

		srcMAC, _ = net.ParseMAC(global.VPNServerMAC)
		dstMAC, _ = net.ParseMAC(global.WebServerMAC)
	} else {
		srcIP = net.ParseIP(global.WebServerIPv6)
		dstIP = net.ParseIP(global.ClientIPv6)

		srcMAC, _ = net.ParseMAC(global.VPNGatewayMAC)
		dstMAC, _ = net.ParseMAC(global.ClientMAC)
	}

	IPLayerStart := global.TransportLayerStartIPv6 + global.ESPHeaderLength
	packetLen := len(packet.Data())
	tcpLayer := packet.Data()[IPLayerStart+40 : packetLen-2]

	csum := csums.TCPcsum(srcIP, dstIP, tcpLayer)
	tcpLayer[16] = byte(csum >> 8)
	tcpLayer[17] = byte(csum)

	decryptedPacket := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(decryptedPacket, gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv6,
		},
		// the original IPv6 header, minus addresses
		gopacket.Payload(packet.Data()[IPLayerStart:IPLayerStart+8]),
		// modified addresses
		gopacket.Payload(srcIP),
		gopacket.Payload(dstIP),
		// tcp data
		gopacket.Payload(tcpLayer),
	)

	if err != nil {
		fmt.Println("Packet creation error: ", err)
	} else {
		send <- decryptedPacket
	}
}
