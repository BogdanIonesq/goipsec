package main

import (
	"github.com/BogdanIonesq/goipsec/pkg/gateway"
)

func main() {
	gw := gateway.NewGateway()
	gw.Start()
}
