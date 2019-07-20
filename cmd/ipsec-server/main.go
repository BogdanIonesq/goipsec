package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
)

const (
	LocalGatewayAddr             = "fe80::f14:e938:f365:86bf"
	RemoteGatewayAddr            = "fe80::6e42:c109:74ed:6dab"
	NetworkLayerDataOffset       = 14
	TransportLayerDataOffsetIPv4 = 34
	TransportLayerDataOffsetIPv6 = 54
)

func main() {
	go listenInside()
	//listenPackets()
}

func listenInside() {
	handle, err := pcap.OpenLive("enp0s3", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	err = handle.SetBPFFilter("udp or esp")
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		fmt.Printf("Packet from %s to %s",
			net.IPv4(packet.Data()[26], packet.Data()[27], packet.Data()[28], packet.Data()[29]).String(),
			net.IPv4(packet.Data()[30], packet.Data()[31], packet.Data()[32], packet.Data()[33]).String())
		go encryptPacket(packet)
	}
}

func encryptPacket(packet gopacket.Packet) {
	encryptedPacket := gopacket.NewSerializeBuffer()

	err := gopacket.SerializeLayers(encryptedPacket, gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x88, 0xb1, 0x11, 0x61, 0x79, 0x7f},
			DstMAC:       net.HardwareAddr{0x08, 0x00, 0x27, 0x11, 0x27, 0x9f},
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
		gopacket.Payload([]byte{1, 2, 3, 4}),
		gopacket.Payload(packet.Data()[NetworkLayerDataOffset:]),
	)

	if err != nil {
		fmt.Println("Packet creation error: ", err)
	}
}

func listen() {
	handle, err := pcap.OpenLive("enp0s3", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	err = handle.SetBPFFilter("esp")
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	if handle, err := pcap.OpenLive("enp0s3", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("esp"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			fmt.Println(packet)

			fmt.Println("writing!")

			forwardPacket := gopacket.NewSerializeBuffer()
			err := gopacket.SerializeLayers(forwardPacket, gopacket.SerializeOptions{},
				&layers.Ethernet{
					SrcMAC:       net.HardwareAddr{0x88, 0xb1, 0x11, 0x61, 0x79, 0x7f},
					DstMAC:       net.HardwareAddr{0x08, 0x00, 0x27, 0x11, 0x27, 0x9f},
					EthernetType: layers.EthernetTypeIPv6,
				},
				gopacket.Payload(packet.Data()[62:]),
			)

			if err != nil {
				fmt.Println("Packet creation error: ", err)
			}

			_ = handle.WritePacketData(forwardPacket.Bytes())
		}
	}
}

func sendPacket() {
	var packet gopacket.Packet

	if handle, err := pcap.OpenOffline("/home/bogdan/bsc-thesis/pcap-files/IPv6-ping.pcap"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		packet = <-packetSource.Packets()
	}

	data := packet.Data()[14:]

	ipsecPacket := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(ipsecPacket, gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x88, 0xb1, 0x11, 0x61, 0x79, 0x7f},
			DstMAC:       net.HardwareAddr{0x08, 0x00, 0x27, 0x11, 0x27, 0x9f},
			EthernetType: layers.EthernetTypeIPv6,
		},
		&layers.IPv6{
			Version:      6,
			TrafficClass: 0,
			FlowLabel:    0,
			Length:       8 + uint16(len(data)),
			NextHeader:   layers.IPProtocolESP,
			HopLimit:     64,
			SrcIP:        net.ParseIP("fe80::f14:e938:f365:86bf"),
			DstIP:        net.ParseIP("fe80::6e42:c109:74ed:6dab"),
		},
		// SPI
		gopacket.Payload([]byte{1, 2, 3, 4}),
		// Sequence Number
		gopacket.Payload([]byte{1, 2, 3, 4}),
		gopacket.Payload(data),
	)

	if err != nil {
		fmt.Println("Packet creation error: ", err)
	}

	// write to wire
	handle, err := pcap.OpenLive("wlp4s0", 1024, false, pcap.BlockForever)

	if err != nil {
		fmt.Println("pcap open error: ", err)
	}
	defer handle.Close()

	err = handle.WritePacketData(ipsecPacket.Bytes())

	if err != nil {
		fmt.Println("Send packet error: ", err)
	}

	fmt.Println("done!")
}
