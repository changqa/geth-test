package main

import (
	"../gethTest"
	"fmt"
	"net"
)

func main() {
	fmt.Println("Start!")
	// IP + port of target geth instance
	targetIp := "127.0.0.1"
	targetPort := "30303"
	// IP + port of our own geth instance
	gethIp := "127.0.0.1"
	gethPort := "30302"
	// Port of this geth-test instanceS
	localIp := ""
	// private key file
	privKeyFile := "keys/priv1"

	// get local address
	c, err := net.Dial("udp", net.JoinHostPort(targetIp, targetPort))
	if err != nil {
		fmt.Println("Target seems to be offline (", err, ")")
	}
	localIp, _, _ = net.SplitHostPort(c.LocalAddr().String())
	c.Close()

	s := gethTest.PingServer{
		TargetIp:   targetIp,
		TargetPort: targetPort,
		GethIp:     gethIp,
		GethPort:   gethPort,
		LocalIp:    localIp,
	}
	s.ParseKeyFile(privKeyFile)
	s.StartPingLoop()

	return
}
