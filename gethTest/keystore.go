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

}

// add adds a private key to the specified key store
func (k *keyStore) add(key *ecdsa.PrivateKey, num int) {
	//fmt.Println(key)

	//store := k.keys[num]

	k.keys[num] = append(k.keys[num], key)
	//store = append(store, key)
	//k.keys[num] = store
	//fmt.Println(k.keys[0][1])
}

// print prints out all stored private keys
func (k *keyStore) print() {
	//fmt.Println(k.keys[0][1])
	fmt.Println("Printing Keys...")
	for i, store := range k.keys {
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
