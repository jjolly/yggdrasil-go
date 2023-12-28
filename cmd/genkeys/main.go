/*
This file generates crypto keys.
It prints out a new set of keys each time if finds a "better" one.
By default, "better" means a higher NodeID (-> higher IP address).
This is because the IP address format can compress leading 1s in the address, to increase the number of ID bits in the address.

If run with the "-sig" flag, it generates signing keys instead.
A "better" signing key means one with a higher TreeID.
This only matters if it's high enough to make you the root of the tree.
*/
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net"
	"runtime"
	"time"
	"flag"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
)

type keySet struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func main() {
	var minWordCount int
	flag.IntVar(&minWordCount, "words", 0, "number of English words to find in IP address")
	flag.Parse()
	threads := runtime.GOMAXPROCS(0)
	fmt.Println("Threads:", threads, "Minimum Words:", minWordCount)
	start := time.Now()
	var currentBest ed25519.PublicKey
	newKeys := make(chan keySet, threads)
	for i := 0; i < threads; i++ {
		go doKeys(newKeys, minWordCount)
	}
	for {
		newKey := <-newKeys
		if isBetter(currentBest, newKey.pub) || len(currentBest) == 0 {
			currentBest = newKey.pub
			fmt.Println("-----", time.Since(start))
			fmt.Println("Priv:", hex.EncodeToString(newKey.priv))
			fmt.Println("Pub:", hex.EncodeToString(newKey.pub))
			addr := address.AddrForKey(newKey.pub)
			fmt.Println("IP:", net.IP(addr[:]).String())
		}
	}
}

func isBetter(oldPub, newPub ed25519.PublicKey) bool {
	for idx := range oldPub {
		if newPub[idx] < oldPub[idx] {
			return true
		}
		if newPub[idx] > oldPub[idx] {
			break
		}
	}
	return false
}

func doKeys(out chan<- keySet, minWordCount int) {
	bestKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for idx := range bestKey {
		bestKey[idx] = 0xff
	}
	for {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}
		hitCount := 0

		if minWordCount > 0 {
			addr := address.AddrForKey(pub)
			// Only search the first half of the IP address, except the first word
			for idx := 2; idx < len(addr)/2; idx += 2 {
				if (addr[idx] == 0xba && addr[idx+1] == 0xbe) ||
					 (addr[idx] == 0xbe && addr[idx+1] == 0xad) ||
					 (addr[idx] == 0xbe && addr[idx+1] == 0xef) ||
					 (addr[idx] == 0xde && addr[idx+1] == 0xad) ||
					 (addr[idx] == 0xde && addr[idx+1] == 0xaf) ||
					 (addr[idx] == 0xde && addr[idx+1] == 0xed) ||
					 (addr[idx] == 0xfa && addr[idx+1] == 0xce) ||
					 (addr[idx] == 0xfe && addr[idx+1] == 0xed) {
					hitCount += 1
				}
			}
		}

		if hitCount < minWordCount || !isBetter(bestKey, pub) {
			continue
		}

		bestKey = pub
		out <- keySet{priv, pub}
	}
}
