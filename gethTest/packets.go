package gethTest

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/rlp"
)

const NodeIDBits = 512

const (
	MacSize  = 256 / 8
	SigSize  = 520 / 8
	HeadSize = MacSize + SigSize
)

// RPC request structures
// (from go-ethereum/p2p/discover/udp.go)
type (
	NodeID [NodeIDBits / 8]byte

	ping struct {
		Version    uint
		From, To   rpcEndpoint
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// pong is the reply to ping.
	pong struct {
		// This field should mirror the UDP envelope address
		// of the ping packet, which provides a way to discover the
		// the external address (after NAT).
		To rpcEndpoint

		ReplyTok   []byte // This contains the hash of the ping packet.
		Expiration uint64 // Absolute timestamp at which the packet becomes invalid.
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// findnode is a query for nodes close to the given target.
	findnode struct {
		Target     NodeID // doesn't need to be an actual public key
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// reply to findnode
	neighbors struct {
		Nodes      []rpcNode
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	rpcNode struct {
		IP  net.IP // len 4 for IPv4 or 16 for IPv6
		UDP uint16 // for discovery protocol
		TCP uint16 // for RLPx protocol
		ID  NodeID
	}

	rpcEndpoint struct {
		IP  net.IP // len 4 for IPv4 or 16 for IPv6
		UDP uint16 // for discovery protocol
		TCP uint16 // for RLPx protocol
	}
)

func makeEndpoint(addr *net.UDPAddr, tcpPort uint16) rpcEndpoint {
	ip := addr.IP.To4()
	return rpcEndpoint{
		IP:  ip,
		UDP: uint16(addr.Port),
		TCP: tcpPort,
	}
}

// from node.go
// recoverNodeID computes the public key used to sign the
// given hash from the signature.
func recoverNodeID(hash, sig []byte) (id NodeID, err error) {
	pubkey, err := secp256k1.RecoverPubkey(hash, sig)
	if err != nil {
		return id, err
	}
	if len(pubkey)-1 != len(id) {
		return id, fmt.Errorf("recovered pubkey has %d bits, want %d bits", len(pubkey)*8, (len(id)+1)*8)
	}
	for i := range id {
		id[i] = pubkey[i+1]
	}
	return id, nil
}

func NewPongPacket(mac []byte, toaddr *net.UDPAddr, priv *ecdsa.PrivateKey) []byte {
	expiration := 20 * time.Second
	req := &pong{
		To:         makeEndpoint(toaddr, 0),
		Expiration: uint64(time.Now().Add(expiration).Unix()),
		ReplyTok:   mac,
	}

	ptype := byte(2)
	headSpace := make([]byte, HeadSize)
	b := new(bytes.Buffer)
	b.Write(headSpace)
	b.WriteByte(ptype)
	err := rlp.Encode(b, req)
	if err := rlp.Encode(b, req); err != nil {
		fmt.Println("Error encoding pong packet (", err, ")")
	}
	packet := b.Bytes()

	sig, err := crypto.Sign(crypto.Keccak256(packet[HeadSize:]), priv)
	if err != nil {
		fmt.Println("Can't sign discv4 packet (", err, ")")
	}
	copy(packet[MacSize:], sig)
	hash := crypto.Keccak256(packet[MacSize:])
	copy(packet, hash)

	return packet
}

func NewPingPacket(ourAddr, targetAddr *net.UDPAddr, ourTcpPort int, priv *ecdsa.PrivateKey) []byte {
	expiration := 20 * time.Second
	ourEndpoint := makeEndpoint(ourAddr, uint16(ourTcpPort))
	req := &ping{
		Version:    4,
		From:       ourEndpoint,
		To:         makeEndpoint(targetAddr, 0),
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	}

	ptype := byte(1)
	headSpace := make([]byte, HeadSize)
	b := new(bytes.Buffer)
	b.Write(headSpace)
	b.WriteByte(ptype)
	err := rlp.Encode(b, req)
	if err := rlp.Encode(b, req); err != nil {
		fmt.Println("Error encoding ping packet (", err, ")")
	}
	packet := b.Bytes()

	sig, err := crypto.Sign(crypto.Keccak256(packet[HeadSize:]), priv)
	if err != nil {
		fmt.Println("Can't sign discv4 packet (", err, ")")
	}
	copy(packet[MacSize:], sig)
	hash := crypto.Keccak256(packet[MacSize:])
	copy(packet, hash)

	return packet
}
