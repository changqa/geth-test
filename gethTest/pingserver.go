package gethTest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	//"crypto/rand"
	//"crypto/x509"
	"encoding/hex"
	//"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	//"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/rlp"
)

type pingServer struct {
	targetIp   net.IP
	targetPort int
	ourIp      net.IP
	ourUdpPort int
	ourTcpPort int
	privKey    *ecdsa.PrivateKey

	targetId *NodeID

	macSize int
	sigSize int

	conn    net.UDPConn
	closing chan struct{}
}

// table of leading zero counts for bytes [0..255]
var lzcount = [256]int{
	8, 7, 6, 6, 5, 5, 5, 5,
	4, 4, 4, 4, 4, 4, 4, 4,
	3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3,
	2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
}

// private functions

func logdist(a, b common.Hash) int {
	lz := 0
	for i := range a {
		x := a[i] ^ b[i]
		if x == 0 {
			lz += 8
		} else {
			lz += lzcount[x]
			break
		}
	}
	return len(a)*8 - lz
}

// returns the bucket number for the given NodeID/TargetNodeID pair
func (s pingServer) bucket() int {

	hashBits := len(common.Hash{}) * 8
	nBuckets := hashBits / 15                // Number of buckets
	bucketMinDistance := hashBits - nBuckets // Log distance of closest bucket

	priv := s.privKey
	pubkey := elliptic.Marshal(secp256k1.S256(), priv.X, priv.Y)
	pubkey = pubkey[1:]
	ownIdSha := crypto.Keccak256Hash(pubkey[:])
	targetIdSha := crypto.Keccak256Hash(s.targetId[:])
	//fmt.Println("Our Public ID:", pubkey)
	//fmt.Println("Our Hash:", ownIdSha)
	//fmt.Println("Their Hash:", targetIdSha)
	d := logdist(targetIdSha, ownIdSha)
	//if d <= bucketMinDistance {
	//return tab.buckets[0]
	//}
	if d <= bucketMinDistance {
		fmt.Println("d <= bucketMinDistance")
		return 0
	}
	fmt.Println("logdist:", d)
	fmt.Println("bucket:", d-bucketMinDistance-1)
	//return tab.buckets[d-bucketMinDistance-1]
	return d
}

func (s pingServer) getTargetId(inBuf []byte) {
	headSize := s.macSize + s.sigSize
	sig := inBuf[s.macSize:headSize]

	fromId, err := recoverNodeID(crypto.Keccak256(inBuf[headSize:]), sig)
	if err != nil {
		fmt.Println("Failed to recover node (", err, ")")
	}

	if s.targetId[0] == 0 {
		for i, _ := range fromId {
			s.targetId[i] = fromId[i]
		}
	}
}

func (s pingServer) ping() {
	// create ping packet
	expiration := 20 * time.Second
	addr := &net.UDPAddr{
		IP:   s.ourIp,
		Port: s.ourUdpPort,
	}
	toaddr := &net.UDPAddr{
		IP:   s.targetIp,
		Port: s.targetPort,
	}
	ourEndpoint := makeEndpoint(addr, uint16(s.ourTcpPort))
	req := &ping{
		Version:    4,
		From:       ourEndpoint,
		To:         makeEndpoint(toaddr, 0),
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	}

	ptype := byte(1)
	headSize := s.macSize + s.sigSize
	headSpace := make([]byte, headSize)

	b := new(bytes.Buffer)
	b.Write(headSpace)
	b.WriteByte(ptype)
	err := rlp.Encode(b, req)
	if err := rlp.Encode(b, req); err != nil {
		fmt.Println("Error encoding ping packet (", err, ")")
	}
	packet := b.Bytes()
	priv := s.privKey
	sig, err := crypto.Sign(crypto.Keccak256(packet[headSize:]), priv)
	if err != nil {
		fmt.Println("Can't sign discv4 packet (", err, ")")
	}
	copy(packet[s.macSize:], sig)

	hash := crypto.Keccak256(packet[s.macSize:])
	copy(packet, hash)

	// send ping packet
	_, err = s.conn.WriteToUDP(packet, toaddr)
	if err != nil {
		fmt.Println("Error sending ping (", err, ")")
	}

	pub := priv.PublicKey
	pbytes := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	fmt.Printf("%s", hex.Dump(pbytes))
}

func (s pingServer) receive() {
	headSize := s.macSize + s.sigSize

	inBuf := make([]byte, 1280)
	s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	readLen, _, err := s.conn.ReadFromUDP(inBuf)
	if err != nil {
		fmt.Println("Error receiving pong (", err, ")")
		return
	}
	inBuf = inBuf[:readLen]
	if len(inBuf) < headSize+1 {
		fmt.Println("Packet too small (", err, ")")
	}
	hash := inBuf[:s.macSize]
	sig := inBuf[s.macSize:headSize]
	sigdata := inBuf[headSize:]

	shouldhash := crypto.Keccak256(inBuf[s.macSize:])
	if !bytes.Equal(hash, shouldhash) {
		fmt.Println("Wrong hash!")
		fmt.Println("Hash:", hash)
		fmt.Println("Should Hash:", shouldhash)
	}

	s.getTargetId(inBuf)

	fromID, err := recoverNodeID(crypto.Keccak256(inBuf[headSize:]), sig)
	if err != nil {
		fmt.Println("Failed to recover node (", err, ")")
	}
	fmt.Println("FromID:", fromID)
	// sigdata[0]:
	// x01 -> ping
	// x02 -> pong
	// x03 -> findnode
	// x04 -> neighbors

	// for now: ignore all but pong packets
	if sigdata[0] != byte(2) {
		return
	}

	largeArray := make([]byte, len(fromID))
	copy(largeArray[:], fromID[:])

	req := new(pong)
	sd := rlp.NewStream(bytes.NewReader(sigdata[1:]), 0)
	err = sd.Decode(req)
	fmt.Println(largeArray)
	fmt.Printf("%s", hex.Dump(largeArray))

	s.bucket()

}

func (s pingServer) pingLoop() {
	fmt.Println("Starting Ping Loop...")
	for {
		select {
		case <-s.closing:
			fmt.Println("Stopping Ping Loop...")
			return
		default:
			s.ping()
			time.Sleep(1 * time.Second)
		}
	}
}

func (s pingServer) receiveLoop() {
	fmt.Println("Starting Receive Loop...")
	for {
		select {
		case <-s.closing:
			fmt.Println("Stopping Receive Loop...")
			return
		default:
			s.receive()
		}
	}
}

// public functions

func (s pingServer) ParseKeyFile(privKeyFile string) {
	fd, err := os.Open(privKeyFile)
	if err != nil {
		fmt.Println("Error opening key file. (", err, ")")
		return
	}
	defer fd.Close()

	buf := make([]byte, 64)
	if _, err := io.ReadFull(fd, buf); err != nil {
		fmt.Println("Error reading key file. (", err, ")")
		return
	}

	key, err := hex.DecodeString(string(buf))
	if err != nil {
		fmt.Println("Error decoding key. (", err, ")")
		return
	}
	priv := s.privKey

	priv.PublicKey.Curve = secp256k1.S256()
	priv.D = new(big.Int).SetBytes(key)

	// The priv.D must not be zero or negative.
	if priv.D.Sign() <= 0 {
		fmt.Println("invalid private key")
		return
	}

	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(key)
	if priv.PublicKey.X == nil {
		fmt.Println("invalid private key")
		return
	}

	fmt.Printf("%s", hex.Dump(buf))

	pubkey := elliptic.Marshal(secp256k1.S256(), priv.X, priv.Y)
	fmt.Printf("%s", hex.Dump(pubkey))

}

func (s pingServer) GeneratePrivateKey() {
}

func (s pingServer) Start() {
	go s.receiveLoop()
	go s.pingLoop()
}

func (s pingServer) Stop() {
	close(s.closing)
	time.Sleep(5 * time.Second)
	fmt.Println("Closing Connection...")
	s.conn.Close()
}

func (s pingServer) ExportPrivateKey() *ecdsa.PrivateKey {
	return s.privKey
}

func NewPingServer(tIp string, tPort, oPort int) *pingServer {
	var err error

	s := new(pingServer)
	s.targetPort = tPort
	s.ourUdpPort = oPort
	s.ourTcpPort = oPort
	s.closing = make(chan struct{})
	s.targetIp, _, err = net.ParseCIDR(tIp + "/24")
	if err != nil {
		fmt.Println("Error parsing target IP (", err, ")")
	}

	s.privKey = new(ecdsa.PrivateKey)
	s.targetId = new(NodeID)

	s.macSize = 256 / 8
	s.sigSize = 520 / 8

	// open connection to target
	addr := net.UDPAddr{
		Port: oPort,
		IP:   net.ParseIP("127.0.0.1"),
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		fmt.Println("Target seems to be offline (", err, ")")
	}
	ourIp := conn.LocalAddr().(*net.UDPAddr).IP
	s.ourIp = ourIp
	s.conn = *conn

	return s
}
