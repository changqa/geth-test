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
	conn       net.UDPConn
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
	//fmt.Println(packet)

	// create new private key
	// TODO: use own private key
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
	//fmt.Println(packet)

	hash := crypto.Keccak256(packet[macSize:])
	copy(packet, hash)
	//fmt.Println(packet)

	// send ping packet
	_, err = s.conn.WriteToUDP(packet, toaddr)
	if err != nil {
		fmt.Println("Error sending ping (", err, ")")
	}
}

func (s PingServer) pingLoop() {
	// open connection to target
	addr := net.UDPAddr{
		Port: 30302,
		IP:   net.ParseIP("127.0.0.1"),
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		fmt.Println("Target seems to be offline (", err, ")")
	}
	defer conn.Close()
	s.conn = *conn

	// this should become a ping loop in the long run
	go s.receiveLoop()
	go s.ping()
	for {
	}
}

func (s PingServer) receiveLoop() {
	macSize := 256 / 8
	sigSize := 520 / 8
	headSize := macSize + sigSize
	for {
		inBuf := make([]byte, 1280)
		readLen, _, err := s.conn.ReadFromUDP(inBuf)
		if err != nil {
			fmt.Println("Error receiving pong (", err, ")")
		}
		inBuf = inBuf[:readLen]
		fmt.Println("Received Package!")
		fmt.Println("length:", readLen)
		fmt.Println("received:", inBuf)
		if len(inBuf) < headSize+1 {
			fmt.Println("Packet too small (", err, ")")
		}
		hash, sig, sigdata := inBuf[:macSize], inBuf[macSize:headSize], inBuf[headSize:]
		shouldhash := crypto.Keccak256(inBuf[macSize:])
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
		fmt.Println("sigdata[0]:", sigdata[0])
		fmt.Println(" ")
		// sigdata[0]:
		// x01 -> ping
		// x02 -> pong
		// x03 -> findnode
		// x04 -> neighbors

		// for now: ignore all but pong packets
		if sigdata[0] != byte(2) {
			continue
		} else {
			fmt.Println("Received Pong Packet")
			req := new(pong)
			sd := rlp.NewStream(bytes.NewReader(sigdata[1:]), 0)
			err = sd.Decode(req)
		}
	}
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
