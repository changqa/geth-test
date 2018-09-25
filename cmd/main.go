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
	flag.IntVar(&ourUdpPort, "oudpport", 30310, "our udp port number")
	flag.IntVar(&ourTcpPort, "otcpport", 30303, "our tcp port number")
	flag.StringVar(&privKeyFile, "keyfile",
		"../keys/0_0", "Private key file")
	//"../keys/privKey_256", "Private key file")
	flag.StringVar(&targetKeyFile, "targetkeyfile",
		"../key", "Target public key file")
	flag.StringVar(&keyDir, "keydir",
		"../keys", "Key directory")
}

func main() {
	s := gethTest.NewPingServer(targetIp, targetPort, ourUdpPort, ourTcpPort)
	//k := gethTest.NewKeyStore(25)

	//for k.KeysTotal() < 425 {
	//s.GeneratePrivateKey()
	//s.ParseTargetIdFile(targetKeyFile)
	//foo := s.PrivateKey()
	//bucketNum := s.BucketNumber()
	//k.Add(foo, bucketNum)
	//}

	s.ParsePrivateKeyFile(privKeyFile)
	//s.GeneratePrivateKey()
	//s.ParseTargetIdFile("/Users/daniel/Desktop/key")
	//s.ParseTargetIdFile()
	s.Start()
	time.Sleep(500 * time.Second)
	s.Stop()
	//foo := s.PrivateKey()
	//s.WriteTargetIdFile(targetKeyFile)

	//s.ParseTargetIdFile("/Users/daniel/Desktop/key")

	//bucketNum := s.BucketNumber()
	//fmt.Println("BucketNum:", bucketNum)
	//fmt.Println("targetId:", s.TargetId())

	//dst := make([]byte, hex.EncodedLen(len(s.TargetId()[:])))
	//hex.Encode(dst, s.TargetId()[:])

	//k.Add(foo, bucketNum)
	//s.GeneratePrivateKey()

	//k.PrintNumberOfKeys()
	//k.WriteKeysToFolder(keyDir)

	return
}
