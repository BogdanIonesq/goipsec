package ipsec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"goipsec/global"
	"goipsec/pkg/config"
	"goipsec/pkg/glog"
	"io"
	"net"
	"os"
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
	var espLayer []byte
	sequenceNumber := make([]byte, 4)
	cryptokey := []byte(os.Getenv("GOIPSEC_PASSWORD"))

	// ESP Next Header field
	nextHeader = int(layers.IPProtocolIPv4)
	if packet.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
		nextHeader = int(layers.IPProtocolIPv6)
	}

	// original packet starting from network layer
	originalPayload := packet.Data()[networkLayerOffset:]
	originalPayloadLen := len(originalPayload)

	// length must be a multiple of aes.BlockSize
	if (originalPayloadLen+2)%aes.BlockSize != 0 {
		padLength = 1
		for ((originalPayloadLen + 2 + padLength) % aes.BlockSize) != 0 {
			padLength++
		}
		padding := make([]byte, padLength)
		originalPayload = append(originalPayload, padding...)
	}

	originalPayload = append(originalPayload, byte(padLength), byte(nextHeader))

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

	espLayer = append(espLayer, []byte{1, 2, 3, 4}...)
	espLayer = append(espLayer, sequenceNumber...)
	espLayer = append(espLayer, ciphertext...)

	encryptedPacket := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(encryptedPacket, gopacket.SerializeOptions{ComputeChecksums: true},
		&layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv6,
		},
		&layers.IPv6{
			Version:      6,
			TrafficClass: 0,
			FlowLabel:    0,
			Length:       uint16(16 + len(ciphertext)),
			NextHeader:   layers.IPProtocolUDP,
			HopLimit:     64,
			SrcIP:        srcIP,
			DstIP:        dstIP,
		},
		&layers.UDP{
			SrcPort: layers.UDPPort(config.Config.SrcUDPPort),
			DstPort: layers.UDPPort(config.Config.DstUDPPort),
			// UDP header (8) + SPI(4) + Sequence Number (4) + len of ciphertext
			Length:   uint16(16 + len(ciphertext)),
			Checksum: 0,
		},
		gopacket.Payload(espLayer),
	)

	if err != nil {
		glog.Logger.Printf("WARNING: packet creation error: %s\n", err)
	} else {
		send <- encryptedPacket
	}
}
