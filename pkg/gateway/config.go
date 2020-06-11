package gateway

import (
	"encoding/json"
	"goipsec/pkg/glog"
	"io/ioutil"
	"net"
	"os"
)

type Config struct {
	Type                string
	ClientIPv4Addr      string
	ClientIPv6Addr      string
	ClientMAC           string
	NodeIPv4Addr        string
	NodeIPv6Addr        string
	NodeMAC             string
	NextHopMAC          string
	NextGatewayIPv6Addr string
}

func (c *Config) init() {
	glog.Logger.Print("checking config file...")
	defer glog.Logger.Print("OK!\n")

	configDir, err := os.UserConfigDir()
	if err != nil {
		glog.Logger.Fatalf("ERROR: user config directory not found\n")
	}

	configFile, err := os.Open(configDir + "/goipsec.json")
	if err != nil {
		glog.Logger.Fatalf("ERROR: config file not found: %s\n", err)
	}
	defer configFile.Close()

	fileBytes, err := ioutil.ReadAll(configFile)
	if err != nil {
		glog.Logger.Fatalf("ERROR: ioutil read: %s\n", err)
	}

	if err := json.Unmarshal(fileBytes, &c); err != nil {
		glog.Logger.Fatalf("ERROR: could not unmarshal config file: %s\n", err)
	}

	if c.Type != "client" && c.Type != "server" {
		glog.Logger.Fatalln("ERROR: unknown gateway type")
	}

	if c.Type == "client" {
		if net.ParseIP(c.ClientIPv4Addr) == nil || net.ParseIP(c.ClientIPv6Addr) == nil {
			glog.Logger.Fatalln("ERROR: value error in config file")
		}
		_, err := net.ParseMAC(c.ClientMAC)
		if err != nil {
			glog.Logger.Fatalln("ERROR: value error in config file")
		}
	}

	if net.ParseIP(c.NodeIPv6Addr) == nil || net.ParseIP(c.NodeIPv4Addr) == nil || net.ParseIP(c.NextGatewayIPv6Addr) == nil {
		glog.Logger.Fatalln("ERROR: value error in config file")
	}

	if _, err := net.ParseMAC(c.NodeMAC); err != nil {
		glog.Logger.Fatalln("ERROR: value error in config file")
	}

	if _, err := net.ParseMAC(c.NextHopMAC); err != nil {
		glog.Logger.Fatalln("ERROR: value error in config file")
	}
}
