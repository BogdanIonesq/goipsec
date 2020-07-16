package gateway

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"goipsec/pkg/csum"
	"goipsec/pkg/glog"
	"io"
	"net"
	"os"
)

const (
	networkLayerOffset = 14
)

func (g *gateway) EncryptPacket(packet gopacket.Packet, send chan gopacket.SerializeBuffer) {
	// choose ESP Next Header field
	nextHeader := int(layers.IPProtocolIPv4)
	if packet.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
		nextHeader = int(layers.IPProtocolIPv6)
	}

	// original packet starting from network layer
	payload := packet.Data()[networkLayerOffset:]
	payloadLen := len(payload)

	// compute padding in order for the payload to be multiple of aes.BlockSize
	padLength := 0
	if (payloadLen+2)%aes.BlockSize != 0 {
		padLength = 1
		for ((payloadLen + 2 + padLength) % aes.BlockSize) != 0 {
			padLength++
		}
		padding := make([]byte, padLength)
		payload = append(payload, padding...)
	}

	// add esp trailer
	payload = append(payload, byte(padLength), byte(nextHeader))

	// retrieve encryption key from env variable and create aes cipher
	enckey := []byte(os.Getenv("GOIPSEC_KEY"))
	block, err := aes.NewCipher(enckey)
	if err != nil {
		panic(err)
	}

	// generate a random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	// encrypt payload
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(payload, payload)

	// complete the esp layer with spi, sequence number and iv
	espLayer := make([]byte, 8+aes.BlockSize+len(payload))
	copy(espLayer[:4], []byte{1, 2, 3, 4})
	copy(espLayer[8:8+aes.BlockSize], iv)
	copy(espLayer[8+aes.BlockSize:], payload)

	// compute hmac over esp layer
	mac := hmac.New(sha512.New512_256, enckey)
	mac.Write(espLayer)
	msgMAC := mac.Sum(nil)

	srcMAC, _ := net.ParseMAC(g.config.NodeMAC)
	dstMAC, _ := net.ParseMAC(g.config.NextHopMAC)
	srcIP := net.ParseIP(g.config.NodeIPv6Addr)
	dstIP := net.ParseIP(g.config.NextGatewayIPv6Addr)

	espPacket := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(espPacket, gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv6,
		},
		&layers.IPv6{
			Version:      6,
			TrafficClass: 0,
			FlowLabel:    0,
			Length:       uint16(8 + len(espLayer) + sha512.Size256),
			NextHeader:   layers.IPProtocolUDP,
			HopLimit:     64,
			SrcIP:        srcIP,
			DstIP:        dstIP,
		},
		&layers.UDP{
			SrcPort: 4500,
			DstPort: 4500,
			Length:  uint16(8 + len(espLayer) + sha512.Size256),
			// checksum is later overwritten
			Checksum: 0,
		},
		gopacket.Payload(espLayer),
		gopacket.Payload(msgMAC),
	)

	// calculate checksum and modify the according bytes
	cs := csum.UDPIPv6(srcIP, dstIP, espPacket.Bytes()[udpPayloadOffset:])
	espPacket.Bytes()[60] = byte(cs >> 8)
	espPacket.Bytes()[61] = byte(cs)

	if err != nil {
		glog.Logger.Printf("WARNING: packet creation error: %s\n", err)
	} else {
		send <- espPacket
	}
}
