package gateway

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

	// separate the original datagram and the esp trailer fields
	nextHeader := int(payload[len(payload)-1])
	padLength := int(payload[len(payload)-2])
	originalDatagram := payload[:len(payload)-2-padLength]

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
	var transportProto int
	var cs uint16
	forgedPacket := gopacket.NewSerializeBuffer()

	if nextHeader == int(layers.IPProtocolIPv4) {
		if g.config.Type == "client" {
			srcIP = originalDatagram[12:16]
			dstIP = net.ParseIP(g.config.ClientIPv4Addr)
		} else {
			srcIP = net.ParseIP(g.config.NodeIPv4Addr)
			dstIP = originalDatagram[16:20]
		}

		transportProto = int(originalDatagram[9])
		if transportProto == 6 {
			cs = csum.TCPIPv4(srcIP, dstIP, originalDatagram[ipv4HeaderLength:])

			originalDatagram[ipv4HeaderLength+16] = byte(cs >> 8)
			originalDatagram[ipv4HeaderLength+17] = byte(cs)
		} else if transportProto == 17 {
			cs = csum.UDPIPv4(srcIP, dstIP, originalDatagram[ipv4HeaderLength:])

			originalDatagram[ipv4HeaderLength+6] = byte(cs >> 8)
			originalDatagram[ipv4HeaderLength+7] = byte(cs)
		}

		// forge the final packet
		err = gopacket.SerializeLayers(forgedPacket, gopacket.SerializeOptions{},
			&layers.Ethernet{
				SrcMAC:       srcMAC,
				DstMAC:       dstMAC,
				EthernetType: layers.EthernetTypeIPv4,
			},
			// the original IPv4 header, until src/dst IP
			gopacket.Payload(originalDatagram[0:12]),
			gopacket.Payload(srcIP),
			gopacket.Payload(dstIP),
			// tcp data
			gopacket.Payload(originalDatagram[ipv4HeaderLength:]),
		)
	} else {
		if g.config.Type == "client" {
			srcIP = originalDatagram[8:24]
			dstIP = net.ParseIP(g.config.ClientIPv6Addr)
		} else {
			srcIP = net.ParseIP(g.config.NodeIPv6Addr)
			dstIP = originalDatagram[24:40]
		}

		transportProto = int(originalDatagram[6])
		if transportProto == 6 {
			cs = csum.TCPIPv6(srcIP, dstIP, originalDatagram[ipv6HeaderLength:])

			originalDatagram[ipv6HeaderLength+16] = byte(cs >> 8)
			originalDatagram[ipv6HeaderLength+17] = byte(cs)
		} else if transportProto == 17 {
			cs = csum.UDPIPv6(srcIP, dstIP, originalDatagram[ipv6HeaderLength:])

			originalDatagram[ipv6HeaderLength+6] = byte(cs >> 8)
			originalDatagram[ipv6HeaderLength+7] = byte(cs)
		}

		err = gopacket.SerializeLayers(forgedPacket, gopacket.SerializeOptions{},
			&layers.Ethernet{
				SrcMAC:       srcMAC,
				DstMAC:       dstMAC,
				EthernetType: layers.EthernetTypeIPv6,
			},
			// the original IPv6 header, until src/dst IP
			gopacket.Payload(originalDatagram[0:8]),
			gopacket.Payload(srcIP),
			gopacket.Payload(dstIP),
			// tcp data
			gopacket.Payload(originalDatagram[ipv6HeaderLength:]),
		)
	}

	// send packet
	if err != nil {
		fmt.Println("Packet creation error: ", err)
	} else {
		send <- forgedPacket
	}
}
