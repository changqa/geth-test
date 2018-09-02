package gethTest

import (
	"bufio"
	"fmt"
	"net"
	"os"
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

}

func (s PingServer) pingLoop() {
	// open connection
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
