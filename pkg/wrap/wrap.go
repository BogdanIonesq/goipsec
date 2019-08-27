package wrap

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"goipsec/global"
	"net"
	"sync/atomic"
)

var seqCount uint32 = 0

func EncryptPacket(packet gopacket.Packet, send chan gopacket.SerializeBuffer) {
	// increase sequence number
	atomic.AddUint32(&seqCount, 1)

	sequenceNumber := make([]byte, 4)
	binary.BigEndian.PutUint32(sequenceNumber, seqCount)

	padLength := []byte{0}

	nextHeader := []byte{4}

	srcMAC, _ := net.ParseMAC(global.VPNGatewayMAC)
	dstMAC, _ := net.ParseMAC(global.VPNServerMAC)

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
			Length:       uint16(8 + len(packet.Data()[global.NetworkLayerDataOffset:]) + 2),
			NextHeader:   layers.IPProtocolESP,
			HopLimit:     64,
			SrcIP:        net.ParseIP(global.VPNGatewayIPv6),
			DstIP:        net.ParseIP(global.VPNServerIPv6),
		},
		// SPI
		gopacket.Payload([]byte{1, 2, 3, 4}),
		// sequence number
		gopacket.Payload(sequenceNumber),
		// payload data
		gopacket.Payload(packet.Data()[global.NetworkLayerDataOffset:]),
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

func DecryptPacket(packet gopacket.Packet, send chan gopacket.SerializeBuffer) {
	srcMAC, _ := net.ParseMAC(global.ClientMAC)
	dstMAC, _ := net.ParseMAC(global.WebServerMAC)

	packetLen := len(packet.Data())

	decryptedPacket := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(decryptedPacket, gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		gopacket.Payload(packet.Data()[(global.TransportLayerDataOffsetIPv6+8):(packetLen-2)]),
	)

	if err != nil {
		fmt.Println("Packet creation error: ", err)
	} else {
		send <- decryptedPacket
	}
}
