package gethTest

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
)

type keyStore struct {
	maxKeysPerBucket int
	keysTotal        int
	keys             [17][]*ecdsa.PrivateKey
}

// WriteKeysToFolder exports the stored keys to individual files, so that they can
// be imported to geth
func (k *keyStore) WriteKeysToFolder(dir string) {
	err := os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		fmt.Println("Error creating key folder (", err, ")")
	}
	for i, store := range k.keys {
		if len(store) < 1 {
			continue
		}
		for j, key := range store {
			filename := dir + "/" + strconv.Itoa(i) + "_" + strconv.Itoa(j)
			fd, err := os.Create(filename)
			if err != nil {
				fmt.Println("Error creating key file (", err, ")")
			}

			dst := make([]byte, hex.EncodedLen(len(key.D.Bytes())))
			hex.Encode(dst, key.D.Bytes())
			fd.Write(dst)

			fd.Close()
			// do stuff
		}
	}
}

// add adds a private key to the specified bucket
func (k *keyStore) add(key *ecdsa.PrivateKey, num int) {
	// check size of bucket
	if len(k.keys[num]) >= k.maxKeysPerBucket {
		//fmt.Println("Bucket", num, "full.")
		return
	}
	// discard duplicates
	for _, k := range k.keys[num] {
		if key == k {
			return
		}
	}

	k.keys[num] = append(k.keys[num], key)
	k.keysTotal = k.keysTotal + 1
}

// printKeys prints out all stored private keys
func (k *keyStore) printKeys() {
	fmt.Println("Printing Keys...")
	for i, store := range k.keys {
		if len(store) < 1 {
			continue
		}
		fmt.Println("Bucket", i)
		for _, key := range store {
			fmt.Println(key.D.Bytes())
		}
	}
}

// PrintNumberOfKeys prints the number of keys per bucket as well as the total
// number of keys stored
func (k *keyStore) printNumberOfKeys() {
	total := 0
	for i, store := range k.keys {
		total = total + len(store)
		fmt.Println("Bucket", i, "->", len(store), "Entries")
	}
	fmt.Println("Total:", total)
}

// public functions

func (k *keyStore) Add(key *ecdsa.PrivateKey, num int) {
	k.add(key, num)
}

func (k *keyStore) PrintKeys() {
	k.printKeys()
}

func (k *keyStore) PrintNumberOfKeys() {
	k.printNumberOfKeys()
}

func (k *keyStore) Keys(bucket int) {

}

func (k *keyStore) KeysTotal() int {
	return k.keysTotal
}

func NewKeyStore(maxKeysPerBucket int) *keyStore {
	k := new(keyStore)
	k.maxKeysPerBucket = maxKeysPerBucket
	k.keysTotal = 0
	return k
}
