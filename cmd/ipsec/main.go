package main

import (
	"bytes"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"goipsec/global"
	"goipsec/pkg/glog"
	"goipsec/pkg/ipsec"
	"net"
)

func main() {
	glog.Logger.Print("INFO: starting goipsec")
	listen()
}

func listen() {
	handle, err := pcap.OpenLive("eth0", 65536, true, pcap.BlockForever)
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
				glog.Logger.Printf("INFO recv TCP packet from %s\n", net.IP(IPLayer.LayerContents()[8:24]).String())

				if bytes.Compare(IPLayer.LayerContents()[8:24], clientAddr) == 0 {
					go ipsec.EncryptPacket(packet, send, true)
				} else {
					go ipsec.EncryptPacket(packet, send, false)
				}
			} else if packet.Layer(layers.LayerTypeIPSecESP) != nil {
				IPLayer := packet.Layer(layers.LayerTypeIPv6)
				glog.Logger.Printf("INFO recv ESP packet from %s\n", net.IP(IPLayer.LayerContents()[8:24]).String())

				if bytes.Compare(IPLayer.LayerContents()[8:24], VPNGatewayAddr) == 0 {
					go ipsec.DecryptPacket(packet, send, true)
				} else {
					go ipsec.DecryptPacket(packet, send, false)
				}
			}
		case packet := <-send:
			err := handle.WritePacketData(packet.Bytes())
			if err != nil {
				fmt.Println("Send packet error: ", err)
			}
		}
	}

}
