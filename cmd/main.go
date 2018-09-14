package main

import (
	"../gethTest"
	"fmt"
	"time"
)

func main() {
	fmt.Println("Start!")
	// IP + port of target geth instance
	targetIp := "127.0.0.1"
	targetPort := uint16(30303)
	// IP + port of our own geth instance
	//gethIp := "127.0.0.1"
	ourPort := uint16(30309)
	// private key file
	privKeyFile := "keys/priv1"

	s := gethTest.NewPingServer(targetIp, targetPort, ourPort)

	s.ParseKeyFile(privKeyFile)
	s.Start()
	time.Sleep(10 * time.Second)
	s.Stop()

	return
}
