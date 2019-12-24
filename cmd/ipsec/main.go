package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"goipsec/pkg/config"
	"goipsec/pkg/glog"
	"goipsec/pkg/ipsec"
	"goipsec/pkg/preflight"
	"net"
)

func main() {
	preflight.Checklist()
	config.NewConfig()
	glog.Logger.Print("INFO: starting goipsec")
	listen()
}

func listen() {
	handle, err := pcap.OpenLive("eth0", 65536, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	// sniff traffic
	err = handle.SetBPFFilter("(tcp and src host 2001:db8:23:42:1::10 or 2001:db8:23:42:1::40) or " +
		"(udp and src host 2001:db8:23:42:1::20 or 2001:db8:23:42:1::30)")
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
				networkLayer := packet.Layer(layers.LayerTypeIPv6)
				if networkLayer == nil {
					// IPv4 packet
					networkLayer = packet.Layer(layers.LayerTypeIPv4)
					glog.Logger.Printf("INFO: encrypting IPv4 TCP packet from %s\n", net.IP(networkLayer.LayerContents()[12:16]).String())

					go ipsec.EncryptPacket(packet, send)
				} else {
					// IPv6 packet
					glog.Logger.Printf("INFO: encrypting IPv6 TCP packet from %s\n", net.IP(networkLayer.LayerContents()[8:24]).String())

					go ipsec.EncryptPacket(packet, send)
				}
			} else if packet.Layer(layers.LayerTypeUDP) != nil {
				networkLayer := packet.Layer(layers.LayerTypeIPv6)
				glog.Logger.Printf("INFO: recv IPv6 UDP packet from %s\n", net.IP(networkLayer.LayerContents()[8:24]).String())

				go ipsec.DecryptPacket(packet, send)
			}
		case packet := <-send:
			err := handle.WritePacketData(packet.Bytes())
			if err != nil {
				glog.Logger.Printf("WARNING: send packet error: %s\n", err)
			}
		}
	}

}
