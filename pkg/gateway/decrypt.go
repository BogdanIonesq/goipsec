package gateway

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"github.com/BogdanIonesq/goipsec/pkg/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"os"
)

const (
	udpPayloadOffset = 62
	ipv6HeaderLength = 40
	ipv4HeaderLength = 20
)

func (g *gateway) DecryptPacket(packet gopacket.Packet, send chan gopacket.SerializeBuffer) {
	espLayer := packet.Data()[udpPayloadOffset : len(packet.Data())-sha512.Size256]
	msgMAC := packet.Data()[len(packet.Data())-sha512.Size256:]

	// first check if hmac values match
	deckey := []byte(os.Getenv("GOIPSEC_KEY"))
	mac := hmac.New(sha512.New512_256, deckey)
	mac.Write(espLayer)
	expectedMAC := mac.Sum(nil)
	if hmac.Equal(msgMAC, expectedMAC) == false {
		glog.Logger.Println("INFO: different hmac values!")
		return
	}

	// extract esp header fields
	//spi := espLayer[:4]
	//seqNumber := espLayer[4:8]
	iv := espLayer[8 : 8+aes.BlockSize]

	// payload includes the original datagram and the esp trailer (both encrypted)
	payload := espLayer[8+aes.BlockSize:]

	// check if payload is of correct length
	if len(payload)%aes.BlockSize != 0 {
		glog.Logger.Println("WARNING: payload is not a multiple of block size")
		return
	}

	// decrypt payload
	block, err := aes.NewCipher(deckey)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(payload, payload)

	// extract trailer fields
	nextHeader := int(payload[len(payload)-1])
	padLength := int(payload[len(payload)-2])

	// compute MACs based on the type of gateway
	var srcMAC, dstMAC net.HardwareAddr
	if g.config.Type == "client" {
		srcMAC, _ = net.ParseMAC(g.config.NodeMAC)
		dstMAC, _ = net.ParseMAC(g.config.ClientMAC)
	} else {
		srcMAC, _ = net.ParseMAC(g.config.NodeMAC)
		dstMAC, _ = net.ParseMAC(g.config.NextHopMAC)
	}

	// spoofed IPs, transport protocol number, checksum and final packet to be forwarded
	var srcIP, dstIP net.IP
	//var transportProto int
	//var cs uint16
	newPacket := gopacket.NewSerializeBuffer()

	if nextHeader == int(layers.IPProtocolIPv4) {
		// encapsulated payload packet begins with IPv4 header
		payloadPacket := gopacket.NewPacket(payload[:len(payload)-2-padLength], layers.LayerTypeIPv4, gopacket.Default)

		ipLayer := payloadPacket.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

		if g.config.Type == "client" {
			srcIP = ipLayer.SrcIP
			dstIP = net.ParseIP(g.config.ClientIPv4Addr)
		} else {
			srcIP = net.ParseIP(g.config.NodeIPv4Addr)
			dstIP = ipLayer.DstIP
		}

		// build the final packet depending on the transport layer
		if udp := payloadPacket.Layer(layers.LayerTypeUDP); udp != nil {
			// UDP as the transport layer
			ipLayer := &layers.IPv4{
				Version:    ipLayer.Version,
				IHL:        ipLayer.IHL,
				TOS:        ipLayer.TOS,
				Length:     ipLayer.Length,
				Id:         ipLayer.Id,
				Flags:      ipLayer.Flags,
				FragOffset: ipLayer.FragOffset,
				TTL:        64,
				Protocol:   ipLayer.Protocol,
				Checksum:   0,
				SrcIP:      srcIP,
				DstIP:      dstIP,
				Options:    nil,
				Padding:    nil,
			}

			udpLayer := udp.(*layers.UDP)
			if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
				glog.Logger.Println("ERROR setting UDP layer checksum!")
				return
			}

			err = gopacket.SerializeLayers(newPacket, gopacket.SerializeOptions{ComputeChecksums: true},
				&layers.Ethernet{
					SrcMAC:       srcMAC,
					DstMAC:       dstMAC,
					EthernetType: layers.EthernetTypeIPv4,
				},
				ipLayer,
				udpLayer,
				gopacket.Payload(udpLayer.LayerPayload()),
			)
		} else {
			// TCP as transport layer
			ipLayer := &layers.IPv4{
				Version:    ipLayer.Version,
				IHL:        ipLayer.IHL,
				TOS:        ipLayer.TOS,
				Length:     ipLayer.Length,
				Id:         ipLayer.Id,
				Flags:      ipLayer.Flags,
				FragOffset: ipLayer.FragOffset,
				TTL:        64,
				Protocol:   ipLayer.Protocol,
				Checksum:   0,
				SrcIP:      srcIP,
				DstIP:      dstIP,
				Options:    nil,
				Padding:    nil,
			}

			tcpLayer := payloadPacket.Layer(layers.LayerTypeTCP).(*layers.TCP)
			if err := tcpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
				glog.Logger.Println("ERROR setting TCP layer checksum!")
			}

			err = gopacket.SerializeLayers(newPacket, gopacket.SerializeOptions{ComputeChecksums: true},
				&layers.Ethernet{
					SrcMAC:       srcMAC,
					DstMAC:       dstMAC,
					EthernetType: layers.EthernetTypeIPv4,
				},
				ipLayer,
				tcpLayer,
				gopacket.Payload(tcpLayer.LayerPayload()),
			)
		}
	} else {
		// encapsulated payload packet begins with IPv6 header
		payloadPacket := gopacket.NewPacket(payload[:len(payload)-2-padLength], layers.LayerTypeIPv6, gopacket.Default)

		ipLayer := payloadPacket.Layer(layers.LayerTypeIPv6).(*layers.IPv6)

		if g.config.Type == "client" {
			srcIP = ipLayer.SrcIP
			dstIP = net.ParseIP(g.config.ClientIPv6Addr)
		} else {
			srcIP = net.ParseIP(g.config.NodeIPv6Addr)
			dstIP = ipLayer.DstIP
		}

		// build the final packet depending on the transport layer
		if udp := payloadPacket.Layer(layers.LayerTypeUDP); udp != nil {
			// UDP as the transport layer
			ipLayer := &layers.IPv6{
				Version:      ipLayer.Version,
				TrafficClass: ipLayer.TrafficClass,
				FlowLabel:    ipLayer.FlowLabel,
				Length:       ipLayer.Length,
				NextHeader:   ipLayer.NextHeader,
				HopLimit:     64,
				SrcIP:        srcIP,
				DstIP:        dstIP,
				HopByHop:     ipLayer.HopByHop,
			}

			udpLayer := udp.(*layers.UDP)
			if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
				glog.Logger.Println("ERROR setting UDP layer checksum!")
				return
			}

			err = gopacket.SerializeLayers(newPacket, gopacket.SerializeOptions{ComputeChecksums: true},
				&layers.Ethernet{
					SrcMAC:       srcMAC,
					DstMAC:       dstMAC,
					EthernetType: layers.EthernetTypeIPv6,
				},
				ipLayer,
				udpLayer,
				gopacket.Payload(udpLayer.LayerPayload()),
			)
		} else {
			// TCP as transport layer
			ipLayer := &layers.IPv6{
				Version:      ipLayer.Version,
				TrafficClass: ipLayer.TrafficClass,
				FlowLabel:    ipLayer.FlowLabel,
				Length:       ipLayer.Length,
				NextHeader:   ipLayer.NextHeader,
				HopLimit:     64,
				SrcIP:        srcIP,
				DstIP:        dstIP,
				HopByHop:     ipLayer.HopByHop,
			}

			tcpLayer := payloadPacket.Layer(layers.LayerTypeTCP).(*layers.TCP)
			if err := tcpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
				glog.Logger.Println("ERROR setting TCP layer checksum!")
			}

			err = gopacket.SerializeLayers(newPacket, gopacket.SerializeOptions{ComputeChecksums: true},
				&layers.Ethernet{
					SrcMAC:       srcMAC,
					DstMAC:       dstMAC,
					EthernetType: layers.EthernetTypeIPv6,
				},
				ipLayer,
				tcpLayer,
				gopacket.Payload(tcpLayer.LayerPayload()),
			)
		}
	}

	// send packet
	if err != nil {
		fmt.Println("Packet creation error: ", err)
	} else {
		send <- newPacket
	}
}
