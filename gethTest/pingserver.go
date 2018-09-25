package gethTest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type pingServer struct {
	targetIp      net.IP
	targetPort    int
	ourIp         net.IP
	ourUdpPort    int
	ourTcpPort    int
	privKey       *ecdsa.PrivateKey
	privKeyBucket int

	targetId *NodeID

	conn    net.UDPConn
	closing chan struct{}
}

// private functions

// getTargetId extracts the NodeID of the target
func (s *pingServer) getTargetId(inBuf []byte) {
	headSize := MacSize + SigSize
	sig := inBuf[MacSize:headSize]

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

// pong sends a single pong-message to the target
func (s *pingServer) pong(buf []byte) {
	mac := buf[:MacSize]
	toaddr := &net.UDPAddr{
		IP:   s.targetIp,
		Port: s.targetPort,
	}

	packet := NewPongPacket(mac, toaddr, s.privKey)

	// send ping packet
	_, err := s.conn.WriteToUDP(packet, toaddr)
	if err != nil {
		fmt.Println("Error sending pong (", err, ")")
	}
}

// ping sends a single ping-message to the target
func (s *pingServer) ping() {
	ourAddr := &net.UDPAddr{
		IP:   s.ourIp,
		Port: s.ourUdpPort,
	}
	targetAddr := &net.UDPAddr{
		IP:   s.targetIp,
		Port: s.targetPort,
	}

	packet := NewPingPacket(ourAddr, targetAddr, s.ourTcpPort, s.privKey)

	// send ping packet
	_, err := s.conn.WriteToUDP(packet, targetAddr)
	if err != nil {
		fmt.Println("Error sending ping (", err, ")")
	}
}

// receive handles incoming datagrams
func (s *pingServer) receive() {
	headSize := MacSize + SigSize

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
	hash := inBuf[:MacSize]
	sig := inBuf[MacSize:headSize]
	sigdata := inBuf[headSize:]

	shouldhash := crypto.Keccak256(inBuf[MacSize:])
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

	// send pongs for incoming pings in order to enter target's buckets
	if sigdata[0] == byte(1) {
		s.pong(inBuf)
		return
	}

	// calculate target bucket number for our NodeID
	priv := s.privKey
	pubkey := elliptic.Marshal(secp256k1.S256(), priv.X, priv.Y)
	pubkey = pubkey[1:]

	targetId := s.targetId[:]

	bucketNum := s.bucket(pubkey, targetId)
	s.privKeyBucket = bucketNum
	fmt.Println("Bucket", bucketNum)

}

// pingLoop manages the ping loop
func (s *pingServer) pingLoop() {
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

// receiveLoop manages the receive loop
func (s *pingServer) receiveLoop() {
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

// ParsePrivateKeyFile extracts a EC private key from the specified file
func (s *pingServer) ParsePrivateKeyFile(privKeyFile string) {
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
}

// WriteTargetIdFile writes the target's NodeID to the specified file
func (s *pingServer) WriteTargetIdFile(file string) {
	fd, err := os.Create(file)
	if err != nil {
		fmt.Println("Error creating target NodeID file (", err, ")")
	}
	defer fd.Close()

	dst := make([]byte, hex.EncodedLen(len(s.TargetId()[:])))
	hex.Encode(dst, s.TargetId()[:])
	fd.Write(dst)
}

// ParseTargetIdFile extracts the target's public key from the specified file
func (s *pingServer) ParseTargetIdFile(file string) {
	fd, err := os.Open(file)
	if err != nil {
		fmt.Println("Error opening key file. (", err, ")")
		return
	}
	defer fd.Close()

	buf := make([]byte, 128)

	if _, err := io.ReadFull(fd, buf); err != nil {
		fmt.Println("Error reading key file. (", err, ")")
		return
	}

	fromId, err := hex.DecodeString(string(buf))
	if err != nil {
		fmt.Println("Error decoding key. (", err, ")")
		return
	}

	for i, _ := range fromId {
		s.targetId[i] = fromId[i]
	}

	// calculate target bucket number for our NodeID
	priv := s.privKey
	pubkey := elliptic.Marshal(secp256k1.S256(), priv.X, priv.Y)
	pubkey = pubkey[1:]

	targetId := s.targetId[:]
	bucketNum := s.bucket(pubkey, targetId)
	s.privKeyBucket = bucketNum
}

// GeneratePrivateKey generates a new EC private key
func (s *pingServer) GeneratePrivateKey() {
	privKey, _ := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	s.privKey = privKey

	// calculate target bucket number for our NodeID
	priv := s.privKey
	pubkey := elliptic.Marshal(secp256k1.S256(), priv.X, priv.Y)
	pubkey = pubkey[1:]

	targetId := s.targetId[:]
	bucketNum := s.bucket(pubkey, targetId)
	s.privKeyBucket = bucketNum
}

// PrivateKey returns the stored private key
func (s *pingServer) PrivateKey() *ecdsa.PrivateKey {
	return s.privKey
}

// TargetId returns the target's public key/NodeID
func (s *pingServer) TargetId() *NodeID {
	return s.targetId
}

// BucketNumber returns the bucket number the current NodeID falls into on the
// target's client
func (s *pingServer) BucketNumber() int {
	return s.privKeyBucket
}

// Start starts the receive and ping loops
func (s *pingServer) Start() {
	go s.receiveLoop()
	go s.pingLoop()
}

// Stop stops the receive and ping loops and closes the UDP connection
func (s *pingServer) Stop() {
	close(s.closing)
	time.Sleep(5 * time.Second)
	fmt.Println("Closing Connection...")
	s.conn.Close()
}

// NewPingServer initializes a new PingServer, sets the variables and returns
// it
func NewPingServer(tIp string, tPort, oUdpPort, oTcpPort int) *pingServer {
	var err error

	s := new(pingServer)
	s.targetPort = tPort
	s.ourUdpPort = oUdpPort
	s.ourTcpPort = oTcpPort
	s.closing = make(chan struct{})
	s.targetIp, _, err = net.ParseCIDR(tIp + "/24")
	if err != nil {
		fmt.Println("Error parsing target IP (", err, ")")
	}
	s.privKey = new(ecdsa.PrivateKey)
	s.targetId = new(NodeID)

	// get local IP
	uconn, err := net.Dial("udp", net.JoinHostPort(s.targetIp.String(), "80"))
	localAddr := uconn.LocalAddr().(*net.UDPAddr)
	uconn.Close()

	// open connection to target
	addr := net.UDPAddr{
		Port: oUdpPort,
		IP:   localAddr.IP,
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
