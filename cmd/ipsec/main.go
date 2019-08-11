package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"goipsec/pkg/wrap"
)

func main() {
	listen()
}

func listen() {
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	// sniff only UDP/ESP traffic for now
	err = handle.SetBPFFilter("(udp and dst host 173.17.17.13) or esp")
	if err != nil {
		panic(err)
	}

	// channels
	send := make(chan gopacket.SerializeBuffer)
	recv := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()

	for {
		select {
		case packet := <-recv:
			if packet.Layer(layers.LayerTypeUDP) != nil {
				fmt.Println("-> got UDP packet!")
				go wrap.EncryptPacket(packet, send)
			} else if packet.Layer(layers.LayerTypeIPSecESP) != nil {
				fmt.Println("-> got ESP packet!")
				go wrap.DecryptPacket(packet, send)
			}
		case packet := <-send:
			err := handle.WritePacketData(packet.Bytes())
			if err != nil {
				fmt.Println("Send packet error: ", err)
			} else {
				fmt.Println("-> sent packet!")
			}
		}
	}

}
