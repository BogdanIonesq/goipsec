package ipsec

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"goipsec/pkg/config"
	"goipsec/pkg/csum"
	"goipsec/pkg/glog"
	"net"
	"os"
)

const (
	udpPayloadOffset = 62
	ipv6HeaderLength = 40
)

func DecryptPacket(packet gopacket.Packet, send chan gopacket.SerializeBuffer) {
	//spi := packet.Data()[udpPayloadOffset : udpPayloadOffset+4]
	//seqNumber := packet.Data()[udpPayloadOffset+4 : udpPayloadOffset+8]
	iv := packet.Data()[udpPayloadOffset+8 : udpPayloadOffset+8+aes.BlockSize]
	ciphertext := packet.Data()[udpPayloadOffset+8+aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		glog.Logger.Print("WARNING: ciphertext is not a multiple of block size")
		return
	}

	cryptokey := []byte(os.Getenv("GOIPSEC_KEY"))
	block, err := aes.NewCipher(cryptokey)
	if err != nil {
		panic(err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	nextHeader := int(ciphertext[len(ciphertext)-1])
	padLength := int(ciphertext[len(ciphertext)-2])

	var srcMAC, dstMAC net.HardwareAddr
	var srcIP, dstIP net.IP
	if config.Config.IsClientGateway {
		srcMAC, _ = net.ParseMAC(config.Config.NodeMAC)
		dstMAC, _ = net.ParseMAC(config.Config.ClientMAC)
	} else {
		srcMAC, _ = net.ParseMAC(config.Config.NodeMAC)
		dstMAC, _ = net.ParseMAC(config.Config.NextHopMAC)
	}

	// original packet before encryption, starting with the network layer
	var originalPacket gopacket.Packet
	if nextHeader == int(layers.IPProtocolIPv4) {
		originalPacket = gopacket.NewPacket(ciphertext[:len(ciphertext)-2-padLength], layers.LayerTypeIPv4, gopacket.Default)

		if config.Config.IsClientGateway {
			srcIP = originalPacket.Data()[12:16]
			dstIP = net.ParseIP(config.Config.ClientIPv4Addr)
		} else {
			srcIP = net.ParseIP(config.Config.NodeIPv4Addr)
			dstIP = originalPacket.Data()[16:20]
		}
	} else {
		originalPacket = gopacket.NewPacket(ciphertext[:len(ciphertext)-2-padLength], layers.LayerTypeIPv6, gopacket.Default)

		if config.Config.IsClientGateway {
			srcIP = originalPacket.Data()[8:24]
			dstIP = net.ParseIP(config.Config.ClientIPv6Addr)
		} else {
			srcIP = net.ParseIP(config.Config.NodeIPv6Addr)
			dstIP = originalPacket.Data()[24:40]
		}
	}

	var cs uint16
	transportLayer := originalPacket.TransportLayer()
	if transportLayer.LayerType() == layers.LayerTypeTCP {
		if nextHeader == int(layers.IPProtocolIPv4) {
			cs = csum.TCPIPv4(srcIP, dstIP, transportLayer.LayerContents())
		} else {
			cs = csum.TCPIPv6(srcIP, dstIP, transportLayer.LayerContents())
		}
	} else if transportLayer.LayerType() == layers.LayerTypeUDP {
		if nextHeader == int(layers.IPProtocolIPv4) {
			cs = csum.UDPIPv4(srcIP, dstIP, transportLayer.LayerContents())
		} else {
			cs = csum.UDPIPv6(srcIP, dstIP, transportLayer.LayerContents())
		}
	}

	transportLayer.LayerContents()[16] = byte(cs >> 8)
	transportLayer.LayerContents()[17] = byte(cs)

	decryptedPacket := gopacket.NewSerializeBuffer()
	if nextHeader == int(layers.IPProtocolIPv4) {
		err = gopacket.SerializeLayers(decryptedPacket, gopacket.SerializeOptions{},
			&layers.Ethernet{
				SrcMAC:       srcMAC,
				DstMAC:       dstMAC,
				EthernetType: layers.EthernetTypeIPv4,
			},
			// the original IPv4 header, until src/dst IP
			gopacket.Payload(originalPacket.Data()[0:12]),
			// modified addresses
			gopacket.Payload(srcIP),
			gopacket.Payload(dstIP),
			// rest of the original ipv4 header, if any options are present TODO
			// gopacket.Payload(originalPacket.Data()[])
			// tcp data
			gopacket.Payload(transportLayer.LayerContents()),
		)
	} else if nextHeader == int(layers.IPProtocolIPv6) {
		err = gopacket.SerializeLayers(decryptedPacket, gopacket.SerializeOptions{},
			&layers.Ethernet{
				SrcMAC:       srcMAC,
				DstMAC:       dstMAC,
				EthernetType: layers.EthernetTypeIPv6,
			},
			// the original IPv6 header, until src/dst IP
			gopacket.Payload(originalPacket.Data()[0:8]),
			// modified addresses
			gopacket.Payload(srcIP),
			gopacket.Payload(dstIP),
			// tcp data
			gopacket.Payload(transportLayer.LayerContents()),
		)
	}

	if err != nil {
		fmt.Println("Packet creation error: ", err)
	} else {
		send <- decryptedPacket
	}
}
