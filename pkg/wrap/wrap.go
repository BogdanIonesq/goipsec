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

var seqNumber uint32 = 0

func EncryptPacket(packet gopacket.Packet, send chan gopacket.SerializeBuffer) {
	// increase sequence number
	atomic.AddUint32(&seqNumber, 1)

	seqnBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(seqnBytes, seqNumber)

	srcMAC, _ := net.ParseMAC(global.ClientGatewayMAC)
	dstMAC, _ := net.ParseMAC(global.VPNGatewayMAC)

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
			Length:       uint16(8 + len(packet.Data()[global.NetworkLayerDataOffset:])),
			NextHeader:   layers.IPProtocolESP,
			HopLimit:     64,
			SrcIP:        net.ParseIP(global.ClientGatewayIPv6),
			DstIP:        net.ParseIP(global.VPNGatewayIPv6),
		},
		// SPI
		gopacket.Payload([]byte{1, 2, 3, 4}),
		// Sequence Number
		gopacket.Payload(seqnBytes),
		gopacket.Payload(packet.Data()[global.NetworkLayerDataOffset:]),
	)

	if err != nil {
		fmt.Println("Packet creation error: ", err)
	} else {
		send <- encryptedPacket
	}
}

func DecryptPacket(packet gopacket.Packet, send chan gopacket.SerializeBuffer) {
	decryptedPacket := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(decryptedPacket, gopacket.SerializeOptions{},
		gopacket.Payload(packet.Data()[global.TransportLayerDataOffsetIPv6:]),
	)

	send <- decryptedPacket
}
