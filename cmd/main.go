package main

import (
	"../gethTest"
	"flag"
	"time"
)

var (
	targetIp   string
	targetPort int
	ourUdpPort int
	ourTcpPort int

	privKeyFile   string
	targetKeyFile string

	keyDir string
)

func init() {
	flag.StringVar(&targetIp, "tip", "127.0.0.1", "target IP address")
	flag.IntVar(&targetPort, "tport", 30303, "target port number")
	flag.IntVar(&ourUdpPort, "oudpport", 30312, "our udp port number")
	flag.IntVar(&ourTcpPort, "otcpport", 30303, "our tcp port number")
	flag.StringVar(&privKeyFile, "keyfile",
		"../keys/0_0", "Private key file")
	flag.StringVar(&targetKeyFile, "targetkeyfile",
		"../key", "Target public key file")
	flag.StringVar(&keyDir, "keydir",
		"../keys", "Key directory")
}

// generateKeys generates the specified number of keys
// for every bucket of the target
func generateKeys(num int) {
	s := gethTest.NewPingServer(targetIp, targetPort, ourUdpPort, ourTcpPort)
	total := 17 * num // as of 09.2018, the number of buckets in geth is set to 17

	k := gethTest.NewKeyStore(num)
	s.ParseTargetIdFile(targetKeyFile)
	for k.KeysTotal() < total {
		s.GeneratePrivateKey()
		foo := s.PrivateKey()
		bucketNum := s.BucketNumber()
		k.Add(foo, bucketNum)
	}

}

// pingLoopRand starts a ping loop using a randomly
// generated private key and NodeID
func pingLoopRand() {
	s := gethTest.NewPingServer(targetIp, targetPort, ourUdpPort, ourTcpPort)
	s.GeneratePrivateKey()
	s.Start()
	time.Sleep(72 * time.Hour)
	s.Stop()

}

// pingLoop starts a ping loop using the private key
// specified in the private key file
func pingLoop() {
	s := gethTest.NewPingServer(targetIp, targetPort, ourUdpPort, ourTcpPort)
	s.ParsePrivateKeyFile(privKeyFile)
	s.Start()
	time.Sleep(72 * time.Hour)
	s.Stop()

}

func main() {
	//generateKeys(25)
	//pingLoopRand()
	pingLoop()

	return
}
