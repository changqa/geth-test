package gethTest

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

type PingServer struct {
	TargetIp   string
	TargetPort string
	GethIp     string
	GethPort   string
	LocalIp    string
	privKey    string
	conn       net.Conn
}

// private functions
func (s PingServer) ping() {
	// create ping packet
	theirIP := net.IPv4(127, 0, 0, 1)
	tcpPort := uint16(30303)
	expiration := 20 * time.Second
	addr := &net.UDPAddr{
		IP:   theirIP,
		Port: 30303,
	}
	toaddr := &net.UDPAddr{
		IP:   theirIP,
		Port: 30303,
	}
	ourEndpoint := makeEndpoint(addr, tcpPort)
	req := &ping{
		Version:    4,
		From:       ourEndpoint,
		To:         makeEndpoint(toaddr, 0),
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	}

	macSize := 256 / 8
	sigSize := 520 / 8
	ptype := byte(1)
	headSize := macSize + sigSize
	headSpace := make([]byte, headSize)

	b := new(bytes.Buffer)
	b.Write(headSpace)
	b.WriteByte(ptype)
	err := rlp.Encode(b, req)
	if err := rlp.Encode(b, req); err != nil {
		fmt.Println("Error encoding ping packet (", err, ")")
	}
	packet := b.Bytes()
	fmt.Println(packet)

	// create new private key???
	ellc := elliptic.P256()
	priv, err := ecdsa.GenerateKey(ellc, rand.Reader)
	if err != nil {
		fmt.Println("Can't generate key (", err, ")")
	}

	sig, err := crypto.Sign(crypto.Keccak256(packet[headSize:]), priv)
	if err != nil {
		fmt.Println("Can't sign discv4 packet (", err, ")")
	}
	copy(packet[macSize:], sig)
	fmt.Println(packet)

	hash := crypto.Keccak256(packet[macSize:])
	copy(packet, hash)
	fmt.Println(packet)

	// send ping packet
	_, err = s.conn.Write(packet)
	if err != nil {
		fmt.Println("Error sending ping (", err, ")")
	}
}

func (s PingServer) pingLoop() {
	// open connection to target
	conn, err := net.Dial("udp", net.JoinHostPort(s.TargetIp, s.TargetPort))
	if err != nil {
		fmt.Println("Target seems to be offline (", err, ")")
	}
	defer conn.Close()
	s.conn = conn

	// ping loop
	s.ping()
}

// public functions
func (s PingServer) ParseKeyFile(privKeyFile string) {
	f, err := os.Open(privKeyFile)
	if err != nil {
		fmt.Println("Key file is missing. (", err, ")")
		return
	}
	defer f.Close()

	// scan first line of key file and store key
	scanner := bufio.NewScanner(f)
	scanner.Scan()
	s.privKey = scanner.Text()

}

func (s PingServer) StartPingLoop() {
	s.pingLoop()
}

func (s PingServer) StopPingLoop() {}

func (s PingServer) PrintData() {
	fmt.Println("foobar")
}
