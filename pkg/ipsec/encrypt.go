package ipsec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"goipsec/pkg/config"
	"goipsec/pkg/csum"
	"goipsec/pkg/glog"
	"io"
	"net"
	"os"
	"sync/atomic"
)

const (
	networkLayerOffset = 14
)

var count uint32

func EncryptPacket(packet gopacket.Packet, send chan gopacket.SerializeBuffer) {
	// ESP Next Header field
	nextHeader := int(layers.IPProtocolIPv4)
	if packet.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
		nextHeader = int(layers.IPProtocolIPv6)
	}

	// original packet starting from network layer
	espPayload := packet.Data()[networkLayerOffset:]
	espPayloadLen := len(espPayload)

	// length must be a multiple of aes.BlockSize
	padLength := 0
	if (espPayloadLen+2)%aes.BlockSize != 0 {
		padLength = 1
		for ((espPayloadLen + 2 + padLength) % aes.BlockSize) != 0 {
			padLength++
		}
		padding := make([]byte, padLength)
		espPayload = append(espPayload, padding...)
	}
	espPayload = append(espPayload, byte(padLength), byte(nextHeader))

	cryptokey := []byte(os.Getenv("GOIPSEC_KEY"))
	block, err := aes.NewCipher(cryptokey)
	if err != nil {
		panic(err)
	}

	// generate a random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	// add the IV to the start of the ciphertext
	ciphertext := append(iv, espPayload...)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], espPayload)

	// increase sequence count
	sequenceNumber := make([]byte, 4)
	atomic.AddUint32(&count, 1)
	binary.BigEndian.PutUint32(sequenceNumber, count)

	// prepend the esp header
	var espLayer []byte
	espLayer = append(espLayer, []byte{1, 2, 3, 4}...)
	espLayer = append(espLayer, sequenceNumber...)
	espLayer = append(espLayer, ciphertext...)

	srcMAC, _ := net.ParseMAC(config.Config.NodeMAC)
	dstMAC, _ := net.ParseMAC(config.Config.NextHopMAC)
	srcIP := net.ParseIP(config.Config.NodeIPv6Addr)
	dstIP := net.ParseIP(config.Config.GatewayIPv6Addr)

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
			Length:       uint16(8 + len(espLayer)),
			NextHeader:   layers.IPProtocolUDP,
			HopLimit:     64,
			SrcIP:        srcIP,
			DstIP:        dstIP,
		},
		&layers.UDP{
			SrcPort: layers.UDPPort(config.Config.SrcUDPPort),
			DstPort: layers.UDPPort(config.Config.DstUDPPort),
			Length:  uint16(8 + len(espLayer)),
			// checksum is later overwritten
			Checksum: 0,
		},
		gopacket.Payload(espLayer),
	)

	// calculate checksum and modify the according bytes
	cs := csum.UDPIPv6(srcIP, dstIP, encryptedPacket.Bytes()[54:])
	encryptedPacket.Bytes()[60] = byte(cs >> 8)
	encryptedPacket.Bytes()[61] = byte(cs)

	if err != nil {
		glog.Logger.Printf("WARNING: packet creation error: %s\n", err)
	} else {
		send <- encryptedPacket
	}
}
