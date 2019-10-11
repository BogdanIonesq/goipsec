package ipsec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"goipsec/global"
	"io"
	"net"
	"sync/atomic"
)

const (
	networkLayerOffset = 14
)

var GatewaySeqCount uint32 = 0
var ServerSeqCount uint32 = 0

func EncryptPacket(packet gopacket.Packet, send chan gopacket.SerializeBuffer, outgoing bool) {
	var srcIP, dstIP net.IP
	var srcMAC, dstMAC net.HardwareAddr
	var padLength, nextHeader int
	sequenceNumber := make([]byte, 4)
	aeskey := []byte("passwordddpasswordddpassworddddd")
	nextHeader = 4

	originalPayload := packet.Data()[networkLayerOffset:]
	originalPayloadLen := len(originalPayload)

	if (originalPayloadLen+2)%aes.BlockSize != 0 {
		padLength = 1
		for ((originalPayloadLen + 2 + padLength) % aes.BlockSize) != 0 {
			padLength++
		}
		padding := make([]byte, padLength)
		originalPayload = append(originalPayload, padding...)
	}

	originalPayload = append(originalPayload, byte(padLength), byte(nextHeader))

	block, err := aes.NewCipher(aeskey)
	if err != nil {
		panic(err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	ciphertext := append(iv, originalPayload...)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], originalPayload)

	if outgoing {
		atomic.AddUint32(&GatewaySeqCount, 1)
		binary.BigEndian.PutUint32(sequenceNumber, GatewaySeqCount)

		srcIP = net.ParseIP(global.VPNGatewayIPv6)
		dstIP = net.ParseIP(global.VPNServerIPv6)

		srcMAC, _ = net.ParseMAC(global.VPNGatewayMAC)
		dstMAC, _ = net.ParseMAC(global.VPNServerMAC)
	} else {
		atomic.AddUint32(&ServerSeqCount, 1)
		binary.BigEndian.PutUint32(sequenceNumber, ServerSeqCount)

		srcIP = net.ParseIP(global.VPNServerIPv6)
		dstIP = net.ParseIP(global.VPNGatewayIPv6)

		srcMAC, _ = net.ParseMAC(global.VPNServerMAC)
		dstMAC, _ = net.ParseMAC(global.VPNGatewayMAC)
	}

	encryptedPacket := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(encryptedPacket, gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv6,
		},
		&layers.IPv6{
			Version:      6,
			TrafficClass: 0,
			FlowLabel:    0,
			Length:       uint16(8 + len(ciphertext)),
			NextHeader:   layers.IPProtocolESP,
			HopLimit:     64,
			SrcIP:        srcIP,
			DstIP:        dstIP,
		},
		gopacket.Payload([]byte{1, 2, 3, 4}),
		gopacket.Payload(sequenceNumber),
		gopacket.Payload(ciphertext),
	)

	if err != nil {
		fmt.Println("Packet creation error: ", err)
	} else {
		send <- encryptedPacket
	}
}
