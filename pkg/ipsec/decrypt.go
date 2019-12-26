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
	ipv4HeaderLength = 20
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

	// decrypt data
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	var srcMAC, dstMAC net.HardwareAddr
	if config.Config.IsClientGateway {
		srcMAC, _ = net.ParseMAC(config.Config.NodeMAC)
		dstMAC, _ = net.ParseMAC(config.Config.ClientMAC)
	} else {
		srcMAC, _ = net.ParseMAC(config.Config.NodeMAC)
		dstMAC, _ = net.ParseMAC(config.Config.NextHopMAC)
	}

	nextHeader := int(ciphertext[len(ciphertext)-1])
	padLength := int(ciphertext[len(ciphertext)-2])

	// original packet before encryption, starting with the network layer
	originalPacket := ciphertext[:len(ciphertext)-2-padLength]

	// spoofed IPs, transport protocol number, checksum and final packet to be forwarded
	var srcIP, dstIP net.IP
	var transportProto int
	var cs uint16
	forgedPacket := gopacket.NewSerializeBuffer()

	if nextHeader == int(layers.IPProtocolIPv4) {
		if config.Config.IsClientGateway {
			srcIP = originalPacket[12:16]
			dstIP = net.ParseIP(config.Config.ClientIPv4Addr)
		} else {
			srcIP = net.ParseIP(config.Config.NodeIPv4Addr)
			dstIP = originalPacket[16:20]
		}

		transportProto = int(originalPacket[9])
		if transportProto == 6 {
			cs = csum.TCPIPv4(srcIP, dstIP, originalPacket[ipv4HeaderLength:])

			originalPacket[ipv4HeaderLength+16] = byte(cs >> 8)
			originalPacket[ipv4HeaderLength+17] = byte(cs)
		} else if transportProto == 17 {
			cs = csum.UDPIPv4(srcIP, dstIP, originalPacket[ipv4HeaderLength:])

			originalPacket[ipv4HeaderLength+6] = byte(cs >> 8)
			originalPacket[ipv4HeaderLength+7] = byte(cs)
		}

		// forge the final packet
		err = gopacket.SerializeLayers(forgedPacket, gopacket.SerializeOptions{},
			&layers.Ethernet{
				SrcMAC:       srcMAC,
				DstMAC:       dstMAC,
				EthernetType: layers.EthernetTypeIPv4,
			},
			// the original IPv4 header, until src/dst IP
			gopacket.Payload(originalPacket[0:12]),
			gopacket.Payload(srcIP),
			gopacket.Payload(dstIP),
			// rest of the original ipv4 header, if any options are present TODO
			// gopacket.Payload(originalPacket.Data()[])
			// tcp data
			gopacket.Payload(originalPacket[ipv4HeaderLength:]),
		)
	} else {
		if config.Config.IsClientGateway {
			srcIP = originalPacket[8:24]
			dstIP = net.ParseIP(config.Config.ClientIPv6Addr)
		} else {
			srcIP = net.ParseIP(config.Config.NodeIPv6Addr)
			dstIP = originalPacket[24:40]
		}

		transportProto = int(originalPacket[6])
		if transportProto == 6 {
			cs = csum.TCPIPv6(srcIP, dstIP, originalPacket[ipv6HeaderLength:])

			originalPacket[ipv6HeaderLength+16] = byte(cs >> 8)
			originalPacket[ipv6HeaderLength+17] = byte(cs)
		} else if transportProto == 17 {
			cs = csum.UDPIPv6(srcIP, dstIP, originalPacket[ipv6HeaderLength:])

			originalPacket[ipv6HeaderLength+6] = byte(cs >> 8)
			originalPacket[ipv6HeaderLength+7] = byte(cs)
		}

		err = gopacket.SerializeLayers(forgedPacket, gopacket.SerializeOptions{},
			&layers.Ethernet{
				SrcMAC:       srcMAC,
				DstMAC:       dstMAC,
				EthernetType: layers.EthernetTypeIPv6,
			},
			// the original IPv6 header, until src/dst IP
			gopacket.Payload(originalPacket[0:8]),
			gopacket.Payload(srcIP),
			gopacket.Payload(dstIP),
			// tcp data
			gopacket.Payload(originalPacket[ipv6HeaderLength:]),
		)
	}

	// send packet
	if err != nil {
		fmt.Println("Packet creation error: ", err)
	} else {
		send <- forgedPacket
	}
}
