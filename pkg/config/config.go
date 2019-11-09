package config

import (
	"encoding/json"
	"goipsec/pkg/glog"
	"io/ioutil"
	"net"
	"os"
)

type config struct {
	IsClientGateway bool
	ClientIPv4Addr  string
	ClientIPv6Addr  string
	ClientMAC       string
	NodeIPv6Addr    string
	NodeMAC         string
	NextHopMAC      string
	GatewayIPv6Addr string
}

var Config config

func NewConfig() {
	configDir, _ := os.UserConfigDir()
	configFile, _ := os.Open(configDir + "/goipsec.json")
	defer configFile.Close()

	fileBytes, err := ioutil.ReadAll(configFile)
	if err != nil {
		glog.Logger.Fatalf("ERROR: ioutil read: %s\n", err)
	}

	if err := json.Unmarshal(fileBytes, &Config); err != nil {
		glog.Logger.Fatalf("ERROR: could not unmarshal config file: %s\n", err)
	}

	if Config.IsClientGateway {
		if net.ParseIP(Config.ClientIPv4Addr) == nil || net.ParseIP(Config.ClientIPv6Addr) == nil {
			glog.Logger.Fatalln("ERROR: value error in config file")
		}
		_, err := net.ParseMAC(Config.ClientMAC)
		if err != nil {
			glog.Logger.Fatalln("ERROR: value error in config file")
		}
	}

	if net.ParseIP(Config.NodeIPv6Addr) == nil || net.ParseIP(Config.GatewayIPv6Addr) == nil {
		glog.Logger.Fatalln("ERROR: value error in config file")
	}

	if _, err := net.ParseMAC(Config.NodeMAC); err != nil {
		glog.Logger.Fatalln("ERROR: value error in config file")
	}

	if _, err := net.ParseMAC(Config.NextHopMAC); err != nil {
		glog.Logger.Fatalln("ERROR: value error in config file")
	}

	glog.Logger.Print("INFO: config file OK")
}
