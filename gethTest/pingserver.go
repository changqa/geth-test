package gethTest

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/rlp"
)

type pingServer struct {
	targetIp   net.IP
	targetPort int
	ourIp      net.IP
	ourUdpPort int
	ourTcpPort int
	privKey    string

	macSize int
	sigSize int

	conn    net.UDPConn
	closing chan struct{}
}

// private functions
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

	// create new private key
	// TODO: use own private key
	ellc := secp256k1.S256()
	priv, err := ecdsa.GenerateKey(ellc, rand.Reader)
	if err != nil {
		fmt.Println("Can't generate key (", err, ")")
	}
	pubkey := elliptic.Marshal(ellc, priv.X, priv.Y)
	privkey := make([]byte, 32)
	blob := priv.D.Bytes()
	copy(privkey[32-len(blob):], blob)
	fmt.Println("=== prikey:", privkey)
	fmt.Println("=== pubkey:", pubkey)

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

	pub := priv.Public()
	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(pub)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY",
		Bytes: x509EncodedPub})

	fmt.Println("Public Key:", pemEncodedPub)
	fmt.Println("Public Key:", x509EncodedPub)
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
	f, err := os.Open(privKeyFile)
	if err != nil {
		fmt.Println("Error parsing key file. (", err, ")")
		return
	}
	defer f.Close()

	// scan first line of key file and store key
	scanner := bufio.NewScanner(f)
	scanner.Scan()
	s.privKey = scanner.Text()
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

func NewPingServer(tIp string, tPort, oPort int) *pingServer {
	var err error

	tIp = tIp + "/24"
	s := new(pingServer)
	s.targetPort = tPort
	s.ourUdpPort = oPort
	s.ourTcpPort = oPort
	s.closing = make(chan struct{})
	s.targetIp, _, err = net.ParseCIDR(tIp)
	if err != nil {
		fmt.Println("Error parsing target IP (", err, ")")
	}

	s.macSize = 256 / 8
	s.sigSize = 520 / 8

	// open connection to target
	addr := net.UDPAddr{
		Port: 30309,
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
