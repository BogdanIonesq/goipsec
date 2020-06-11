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
		filter := fmt.Sprintf("((tcp or udp) and (src host %s or %s)) or (udp and src host %s and dst port %d)",
			g.config.ClientIPv4Addr, g.config.ClientIPv6Addr, g.config.NextGatewayIPv6Addr, 4500)
		err := handle.SetBPFFilter(filter)
		if err != nil {
			panic(err)
		}
	} else {
		err := handle.SetBPFFilter("tcp or udp")
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
			switch udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer {
			case nil:
				// tcp packet
				go g.EncryptPacket(packet, send)
			default:
				udp, _ := udpLayer.(*layers.UDP)
				if udp.DstPort == 4500 {
					go g.DecryptPacket(packet, send)
				} else {
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
