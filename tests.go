package main

import (
	blst "github.com/supranational/blst/bindings/go"

	"crypto/rand"
	"fmt"
	"math/big"

	"encoding/base64"
	"encoding/hex"

	"github.com/hbakhtiyor/schnorr"
	"github.com/tendermint/tendermint/crypto/ed25519"
)

func ftests() {
	//tests
	//bls rnd
	fmt.Println("Bls rnd:")

	skm := [32]byte{0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09}
	//_, _ = rand.Read(ikm[:])
	sk := blst.KeyGen(skm[:])

	pk := new(PublicKey).From(sk)

	var dst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
	msg := []byte("hello foo")
	sig := new(Signature).Sign(sk, msg, dst)

	sigc := sig.Compress()

	if !sig.Verify(true, pk, true, msg, dst) {
		fmt.Println("ERROR: Invalid!")
	} else {
		fmt.Println("Valid!")
		fmt.Println(skm, sk, pk, msg)
		fmt.Println(len(sigc))
	}

	//schnorr btc rnd
	fmt.Println("scnorrbtc rnd:")
	var kkm [32]byte
	_, _ = rand.Read(kkm[:])

	//schnorr btc from.seed                                     ▒
	fmt.Println("scnorrbtc from seed:")

	var message [32]byte

	privateKey, _ := new(big.Int).SetString("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF", 16)
	msg, _ = hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
	copy(message[:], msg)

	signature, err := schnorr.Sign(privateKey, message)
	if err != nil {
		fmt.Printf("The signing is failed: %v\n", err)
	}
	fmt.Printf("The signature is: %x\n", signature)
	fmt.Println(len(signature))
}

func stests() {
	//scnorr64b rnd
	fmt.Println("scnorr64 rnd")

	msg := []byte("hello foo")

	privkey1 := ed25519.GenPrivKey()
	pubkey := privkey1.PubKey()
	sig2, _ := privkey1.Sign(msg)

	if !pubkey.VerifySignature(msg, sig2) {
		fmt.Println("ERROR: Invalid!")
	} else {
		fmt.Println("Valid!")
		//fmt.Println(privkey1,pubkey,msg)
	}

	//scnorr64b from seed
	fmt.Println("scnorr64 from seed")

	privkey := ed25519.GenPrivKeyFromSecret([]byte("Ilove-you!"))
	pubkey = privkey.PubKey()

	sig2, _ = privkey.Sign(msg)

	if !pubkey.VerifySignature(msg, sig2) {
		fmt.Println("ERROR: Invalid!")
	} else {
		fmt.Println("Valid!")
		//fmt.Println(privkey,pubkey,msg)
	}
}

func test() {
	//ftests()
	//stests()
	secret := []byte("Iloveyou!")
	source := []byte{0, 0, 0, 0}
	target := []byte{0, 0, 0, 1}
	amount := []byte{0, 5, 0, 0}

	counter := []byte{0, 0, 0, 0}

	fmt.Println("Creating account...")

	sprivkey, spubkey := sKeyPair(secret)
	spriv := make([]byte, 128)
	base64.StdEncoding.Encode(spriv, sprivkey.Bytes())
	spub := make([]byte, 128)
	base64.StdEncoding.Encode(spub, spubkey.Bytes())
	var ikm [32]byte
	addr := spubkey.Address()
	bprivkey, bpubkey, blspk, pop, dst := blsKeyPair(ikm[:], source, counter) // secret)
	fmt.Println("address: ", addr, "scnorr pubkey:", string(spub), "privkey: ", string(spriv), "Bls keypair:", bprivkey, bpubkey, "dst:", dst)

	account := createAccountTx(sprivkey, spubkey.Bytes(), blspk, pop, source, amount, counter)
	amount = []byte{0, 0, 0, 1}

	counter = []byte{0, 0, 0, 1}
	transferWithUpdateTx(sprivkey, source, target, amount, ikm[:], counter)

	if account.Address == nil {
		fmt.Println("nil data. Querying...")
		query(account.blsPubKey)
	}
	q := query(account.blsPubKey)
	fmt.Println("Query tx by pk: ", q)
	fmt.Println("Query tx by address...")

	//Val, ok := q.(string)
	//if ok {
	/*
		Val := string(q)
			decoded, err := base64.StdEncoding.DecodeString(Val)
			if err != nil {
				fmt.Println("Error decoding base64 string:", err)
				return
			}
			fmt.Println(decoded)*/
	q = query(q)
	//}

	//Val, ok = q.(string)
	//if ok {
	/*
			Val = string(q)
		                decoded, _ = base64.StdEncoding.DecodeString(Val)
				fmt.Println("decoded: ", decoded, " of length: ", len(decoded))
			//}
	*/
	query([]byte{0, 0, 0, 0})

	fmt.Println("Transfer tx...")

	counter = []byte{0, 0, 0, 2}
	transferTx(sprivkey, source, target, amount, counter)

	counter = []byte{0, 0, 0, 3}
	UpdateTx(sprivkey, source, ikm[:], counter)

	counter = []byte{0, 0, 0, 4}

	bprivkey, bpubkey, blspk, pop, dst = blsKeyPair(ikm[:], source, counter) // secret)

	account = changeAccountKeyTx(sprivkey, spubkey.Bytes(), blspk, pop, source, counter)

	//fmt.Println("Bls pubkey:", blspk, "pop", pop)

	counter = []byte{0, 0, 0, 5}
	stakeTx(sprivkey, source, amount, counter)
	fmt.Println(spubkey)

	counter = []byte{0, 0, 0, 6}
	amount = []byte{0, 2, 0, 8}
	stakeTx(sprivkey, source, amount, counter)

	counter = []byte{0, 0, 0, 7}
	releaseTx(sprivkey, source, counter)

	query([]byte{0, 0, 0, 0, 0, 0, 0, 6})

	counter = []byte{0, 0, 0, 8}
	payload := counter
	contractTx(sprivkey, source, amount, target, payload, counter)
	//verifySchnorr(pubkey, sig, hash)
}
