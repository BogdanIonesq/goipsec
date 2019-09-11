package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"goipsec/pkg/wrap"
)

func main() {
	fmt.Printf("starting goipsec...\n")
	listen()
}

func listen() {
	handle, err := pcap.OpenLive("eth0", 1600, false, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	// sniff only UDP/ESP traffic for now
	err = handle.SetBPFFilter("(tcp and src host 2001:db8:23:42:1::10) or esp or (tcp and src host 2001:db8:23:42:1::40)")
	if err != nil {
		panic(err)
	}

	// channels
	send := make(chan gopacket.SerializeBuffer)
	recv := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()

	for {
		select {
		case packet := <-recv:
			if packet.Layer(layers.LayerTypeTCP) != nil {
				fmt.Println("-> got TCP packet!")
				fmt.Println(packet.String())
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
