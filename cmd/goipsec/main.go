package main

import "goipsec/pkg/gateway"

func main() {
	gw := gateway.NewGateway()
	gw.Start()
}
