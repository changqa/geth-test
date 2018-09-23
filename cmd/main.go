package main

import (
	"../gethTest"
	//"crypto/ecdsa"
	"flag"
	"fmt"
	"time"
)

func main() {
	targetIp := flag.String("tip", "127.0.0.1", "target IP address")
	targetPort := flag.Int("tport", 30303, "target port number")
	ourPort := flag.Int("oport", 30309, "our port number")
	privKeyFile := flag.String("keyfile", "../keys/privKey_256", "Private key file")

	s := gethTest.NewPingServer(*targetIp, *targetPort, *ourPort)
	//t := gethTest.NewPingServer(*targetIp, *targetPort, 33333)
	k := gethTest.NewKeyStore()

	fmt.Println(privKeyFile)

	//s.ParseKeyFile(*privKeyFile)
	s.GeneratePrivateKey()
	s.Start()
	time.Sleep(3000 * time.Second)
	s.Stop()
	//foo := s.ExportPrivateKey()

	//k.Add(foo, 0)
	//t.ParseKeyFile("../keys/privKey_255")
	//t.GeneratePrivateKey()
	//bar := t.ExportPrivateKey()
	//k.Add(bar, 0)
	//k.Add(bar, 0)

	k.Print()

	return
}
