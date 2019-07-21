package main

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
)

const (
	LocalGatewayMAC              = "08:00:27:ad:c3:95"
	RemoteGatewayMAC             = "08:00:27:11:27:9f"
	LocalGatewayAddr             = "fe80::f14:e938:f365:86bf"
	RemoteGatewayAddr            = "fe80::6e42:c109:74ed:6dab"
	NetworkLayerDataOffset       = 14
	TransportLayerDataOffsetIPv4 = 34
	TransportLayerDataOffsetIPv6 = 54
)

func main() {
	//listen()
	fmt.Println([4]byte{})
}

func listen() {
	handle, err := pcap.OpenLive("enp0s3", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	// sniff only UDP/ESP traffic for now
	err = handle.SetBPFFilter("(udp and dst host 192.168.2.221) or esp")
	if err != nil {
		panic(err)
	}

	// channels
	send := make(chan gopacket.SerializeBuffer)
	recv := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()

	// esp sequence number counter
	var seq uint32

	for {
		select {
		case packet := <-recv:
			if packet.Layer(layers.LayerTypeUDP) != nil {
				fmt.Println("-> got UDP packet!")
				seq++
				go encryptPacket(packet, send, seq)
			} else if packet.Layer(layers.LayerTypeIPSecESP) != nil {
				fmt.Println("-> got ESP packet!")
				go decryptPacket(packet, send)
			}
		case packet := <-send:
			err := handle.WritePacketData(packet.Bytes())
			fmt.Println("-> sent packet!")

			if err != nil {
				fmt.Println("Send packet error: ", err)
			}
		}
	}

}

func encryptPacket(packet gopacket.Packet, send chan gopacket.SerializeBuffer, seq uint32) {
	srcMAC, _ := net.ParseMAC(LocalGatewayMAC)
	dstMAC, _ := net.ParseMAC(RemoteGatewayMAC)
	seqn := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(seqn, seq)

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
			Length:       8 + uint16(len(packet.Data()[NetworkLayerDataOffset:])),
			NextHeader:   layers.IPProtocolESP,
			HopLimit:     64,
			SrcIP:        net.ParseIP(LocalGatewayAddr),
			DstIP:        net.ParseIP(RemoteGatewayAddr),
		},
		// SPI
		gopacket.Payload([]byte{1, 2, 3, 4}),
		// Sequence Number
		gopacket.Payload(seqn),
		gopacket.Payload(packet.Data()[NetworkLayerDataOffset:]),
	)

	if err != nil {
		fmt.Println("Packet creation error: ", err)
	} else {
		send <- encryptedPacket
	}
}

func decryptPacket(packet gopacket.Packet, send chan gopacket.SerializeBuffer) {
	decryptedPacket := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(decryptedPacket, gopacket.SerializeOptions{},
		gopacket.Payload(packet.Data()[TransportLayerDataOffsetIPv6:]),
	)

	send <- decryptedPacket
}
