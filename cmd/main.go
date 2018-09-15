package main

import (
	"../gethTest"
	"flag"
	"time"
)

func main() {
	targetIp := flag.String("tip", "127.0.0.1", "target IP address")
	targetPort := flag.Int("tport", 30303, "target port number")
	ourPort := flag.Int("oport", 30309, "our port number")
	privKeyFile := flag.String("key", "keys/priv1", "Private key file")

	s := gethTest.NewPingServer(*targetIp, *targetPort, *ourPort)

	s.ParseKeyFile(*privKeyFile)
	s.Start()
	time.Sleep(10 * time.Second)
	s.Stop()

	return
}
