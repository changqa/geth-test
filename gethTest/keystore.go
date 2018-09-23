package gethTest

import (
	"crypto/ecdsa"
	"fmt"
)

type keyStore struct {
	keys [255][]*ecdsa.PrivateKey
}

// exportToFiles exports the stored keys to individual files, so that they can
// be imported by geth
func (k *keyStore) exportToFiles(folder string) {
	//for i, store := range k.keys {
	//for _, key := range store {
	//// do stuff
	//}
	//}
}

// add adds a private key to the specified key store
func (k *keyStore) add(key *ecdsa.PrivateKey, num int) {
	// ignore duplicates
	for _, k := range k.keys[num] {
		if key == k {
			return
		}
	}

	k.keys[num] = append(k.keys[num], key)
}

// print prints out all stored private keys
func (k *keyStore) print() {
	//fmt.Println(k.keys[0][1])
	fmt.Println("Printing Keys...")
	for i, store := range k.keys {
		if len(store) < 1 {
			continue
		}
		fmt.Println("Bucket", i)
		for _, key := range store {
			fmt.Println(key)
		}
	}
}

// public functions
func NewKeyStore() *keyStore {
	k := new(keyStore)
	return k
}

func (k *keyStore) Add(key *ecdsa.PrivateKey, num int) {
	k.add(key, num)
}

func (k *keyStore) Print() {
	k.print()
}
