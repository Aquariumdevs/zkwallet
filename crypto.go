package main

import (
	"golang.org/x/crypto/sha3"

	blst "github.com/supranational/blst/bindings/go"

	"crypto/rand"
	"fmt"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/ed25519"
)

func bls(sk PrivateKey, hash, data, dst []byte) {

}

func blsCompressedVerify(sig *Signature, sg, blspk, msg, dst []byte) bool {
	if sig.VerifyCompressed(sg, false, blspk, true, msg, dst) {
		//fmt.Println("Pop Valid!")
		return true
	} else {
		//fmt.Println("fuck")
		return false
	}
}

func blsVerify(sig *Signature, pk PublicKey, msg, dst []byte) bool {
	if !sig.Verify(true, &pk, true, msg, dst) {
		fmt.Println("ERROR: Invalid!")
		return false
	} else {
		fmt.Println("Valid!")
		return true
	}
}

type PublicKey = blst.P1Affine
type PrivateKey = blst.P1Affine
type Signature = blst.P2Affine
type AggregateSignature = blst.P2Aggregate
type AggregatePublicKey = blst.P1Aggregate

func blsKeyPair(secretseed, source, counter []byte) (blst.SecretKey, PublicKey, []byte, []byte, []byte) {
	//Bls from seed
	//fmt.Println("Bls from seed:")

	var dst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")

	var ikm [32]byte
	copy(ikm[:], secretseed)
	secret := hashData(ikm[:])

	sk := blst.KeyGen(secret)

	pk := new(PublicKey).From(sk)

	blspk := pk.Compress()

	//proof of possesion
	h := sha3.New256()
	h.Write(blspk)
	h.Write(source)
	h.Write(counter)
	sha3 := h.Sum(nil)

	sig := new(Signature).Sign(sk, sha3, dst)
	pop := sig.Compress()

	//fmt.Println("____", source, counter)
	//fmt.Println("Hash: ", sha3)
	//fmt.Println("POP: ", pop)
	//fmt.Println("BLSPK: ", blspk)

	//fmt.Println(blspk, len(blspk), sha3, pop, len(pop))
	blsCompressedVerify(sig, pop, blspk, sha3, dst)
	return *sk, *pk, blspk, pop, dst
}

func sKeyPair(secret []byte) (crypto.PrivKey, crypto.PubKey) {
	privkey := ed25519.GenPrivKeyFromSecret(secret)
	pubkey := privkey.PubKey()
	return privkey, pubkey
}

func verifySchnorr(pubkey crypto.PubKey, sig2, hash []byte) {
	if !pubkey.VerifySignature(hash, sig2) {
		fmt.Println("ERROR: Invalid!")
	} else {
		fmt.Println("Valid!")
	}
}

// Function to generate keys from a secret
func generateKeysFromSecret(secret, source, counter []byte) (sprivkey crypto.PrivKey, spubkey crypto.PubKey, blspk, pop, dst []byte, err error) {
	// Generate keys using the provided secret, source, and counter
	sprivkey, spubkey = sKeyPair(secret)
	_, _, blspk, pop, dst = blsKeyPair(secret, source, counter)

	// Check for any errors during key generation
	//if err != nil {
	//    return nil, nil, nil, nil, nil, err
	//}

	return sprivkey, spubkey, blspk, pop, dst, nil
}

// Function to generate keys from a secret
func generateRandomKeys(source, counter []byte) (secret []byte, sprivkey crypto.PrivKey, spubkey crypto.PubKey, blspk, pop, dst []byte, err error) {
	secret = make([]byte, 32)
	// read random data into the buffer
	_, err = rand.Read(secret)
	if err != nil {
		panic(err)
	}

	sprivkey, spubkey = sKeyPair(secret)
	_, _, blspk, pop, dst = blsKeyPair(secret, source, counter)

	//fmt.Println("NEWPUBKEY:    ", spubkey.Bytes())
	return secret, sprivkey, spubkey, blspk, pop, dst, nil
}
