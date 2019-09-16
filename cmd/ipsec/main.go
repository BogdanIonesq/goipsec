package main

import (
	"bytes"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"goipsec/global"
	"goipsec/pkg/ipsec"
	"net"
)

func main() {
	fmt.Printf("starting goipsec...\n")
	listen()
}

func listen() {
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	// sniff traffic
	err = handle.SetBPFFilter("(tcp and src host 2001:db8:23:42:1::10) or esp or (tcp and src host 2001:db8:23:42:1::40)")
	if err != nil {
		panic(err)
	}

	// channels
	send := make(chan gopacket.SerializeBuffer)
	recv := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()

	// convert IP addresses now to avoid re-calling same functions
	clientAddr := net.ParseIP(global.ClientIPv6)
	VPNGatewayAddr := net.ParseIP(global.VPNGatewayIPv6)

	for {
		select {
		case packet := <-recv:
			if packet.Layer(layers.LayerTypeTCP) != nil {
				IPLayer := packet.Layer(layers.LayerTypeIPv6)
				if bytes.Compare(IPLayer.LayerContents()[8:24], clientAddr) == 0 {
					fmt.Println("-> got TCP packet from client")
					go ipsec.EncryptPacket(packet, send, true)
				} else {
					fmt.Println("-> got TCP packet from server")
					go ipsec.EncryptPacket(packet, send, false)
				}
			} else if packet.Layer(layers.LayerTypeIPSecESP) != nil {
				IPLayer := packet.Layer(layers.LayerTypeIPv6)
				if bytes.Compare(IPLayer.LayerContents()[8:24], VPNGatewayAddr) == 0 {
					fmt.Println("-> got ESP packet from VPN gateway")
					go ipsec.DecryptPacket(packet, send, true)
				} else {
					fmt.Println("-> got ESP packet from VPN server")
					go ipsec.DecryptPacket(packet, send, false)
				}
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
