package gateway

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"goipsec/pkg/glog"
	"os"
)

type gateway struct {
	config    Config
	seq       uint32
	remoteSeq uint32
	spi       uint32
}

func NewGateway() *gateway {
	return new(gateway)
}

func (g *gateway) Start() {
	// populate config struct from config file
	g.config.init()

	// check crypto key
	g.checkKey()

	// start listening
	g.listen()
}

func (g *gateway) checkKey() {
	glog.Logger.Print("checking GOIPSEC_KEY...")
	defer glog.Logger.Print("OK!\n")

	if len(os.Getenv("GOIPSEC_KEY")) != 32 {
		glog.Logger.Fatalln("ERROR: env variable GOIPSEC_KEY not correctly set")
	}
}

func (g *gateway) listen() {
	handle, err := pcap.OpenLive("eth0", 65536, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	// sniff traffic
	if g.config.Type == "client" {
		filter := fmt.Sprintf("((tcp or udp) and (src host %s or %s) and src port %d) or (udp and src host %s and dst port %d)",
			g.config.ClientIPv4Addr, g.config.ClientIPv6Addr, g.config.ClientPort, g.config.NextGatewayIPv6Addr, 4500)
		err := handle.SetBPFFilter(filter)
		if err != nil {
			panic(err)
		}
	} else {
		filter := fmt.Sprintf("(tcp and dst port %d) or (udp and src host %s and dst port %d)", g.config.ClientPort, g.config.NextGatewayIPv6Addr, 4500)
		err := handle.SetBPFFilter(filter)
		if err != nil {
			panic(err)
		}
	}

	// channels
	send := make(chan gopacket.SerializeBuffer)
	recv := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()

	for {
		select {
		case packet := <-recv:
			switch udp := packet.Layer(layers.LayerTypeUDP); udp {
			case nil:
				// tcp packet
				tcpLayer := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

				glog.Logger.Printf("encrypting TCP packet (src port %d | dst port %d)...\n", tcpLayer.SrcPort, tcpLayer.DstPort)
				go g.EncryptPacket(packet, send)
			default:
				// udp packet
				udpLayer, _ := udp.(*layers.UDP)
				if udpLayer.DstPort == 4500 {
					glog.Logger.Println("decrypting ESP packet...")
					go g.DecryptPacket(packet, send)
				} else {
					glog.Logger.Printf("encrypting UDP packet (src port %d | dst port %d)...\n", udpLayer.SrcPort, udpLayer.DstPort)
					go g.EncryptPacket(packet, send)
				}
			}
		case packet := <-send:
			err := handle.WritePacketData(packet.Bytes())
			if err != nil {
				glog.Logger.Printf("WARNING: send packet error: %s\n", err)
			}
		}
	}

}
