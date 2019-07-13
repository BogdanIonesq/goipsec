package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	if handle, err := pcap.OpenOffline("/home/bogdan/bsc-thesis/pcap-files/UDP-hello.pcap"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for packet := range packetSource.Packets() {
			handlePacket(packet)
		}
	}
}

func handlePacket (packet gopacket.Packet) {
	for _, layer := range packet.Layers() {
		fmt.Println("PACKET LAYER:", layer.LayerType())
	}
}