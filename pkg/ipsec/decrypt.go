package ipsec

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"goipsec/global"
	"goipsec/pkg/csum"
	"goipsec/pkg/glog"
	"net"
	"os"
)

const (
	espPayloadOffset = 62
	ipv6HeaderLength = 40
)

func DecryptPacket(packet gopacket.Packet, send chan gopacket.SerializeBuffer, outgoing bool) {
	var srcIP, dstIP net.IP
	var srcMAC, dstMAC net.HardwareAddr
	cryptokey := []byte(os.Getenv("GOIPSEC_KEY"))

	// separate the IV and ciphertext portions
	iv := packet.Data()[espPayloadOffset : espPayloadOffset+aes.BlockSize]
	ciphertext := packet.Data()[espPayloadOffset+aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		glog.Logger.Print("WARNING: ciphertext is not a multiple of block size")
		return
	}

	block, err := aes.NewCipher(cryptokey)
	if err != nil {
		panic(err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	//nextHeader := int(ciphertext[len(ciphertext)-1])
	padLength := int(ciphertext[len(ciphertext)-2])
	originalPayload := ciphertext[:len(ciphertext)-2-padLength]

	if outgoing {
		srcIP = net.ParseIP(global.VPNServerIPv6)
		dstIP = net.ParseIP(global.WebServerIPv6)

		srcMAC, _ = net.ParseMAC(global.VPNServerMAC)
		dstMAC, _ = net.ParseMAC(global.WebServerMAC)
	} else {
		srcIP = net.ParseIP(global.WebServerIPv6)
		dstIP = net.ParseIP(global.ClientIPv6)

		srcMAC, _ = net.ParseMAC(global.VPNGatewayMAC)
		dstMAC, _ = net.ParseMAC(global.ClientMAC)
	}

	tcpLayer := originalPayload[ipv6HeaderLength:]

	csum := csum.TCPIPv6(srcIP, dstIP, tcpLayer)
	tcpLayer[16] = byte(csum >> 8)
	tcpLayer[17] = byte(csum)

	decryptedPacket := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(decryptedPacket, gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv6,
		},
		// the original IPv6 header, minus addresses
		gopacket.Payload(originalPayload[0:8]),
		// modified addresses
		gopacket.Payload(srcIP),
		gopacket.Payload(dstIP),
		// tcp data
		gopacket.Payload(tcpLayer),
	)

	if err != nil {
		fmt.Println("Packet creation error: ", err)
	} else {
		send <- decryptedPacket
	}
}
