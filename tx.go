package main

import (
	blst "github.com/supranational/blst/bindings/go"

	"fmt"

	"github.com/fatih/color"

	"encoding/base64"
	"encoding/hex"

	"io/ioutil"

	"net/http"
	"net/url"

	"github.com/tendermint/tendermint/crypto"
)

var colorRed = color.New(color.FgRed).SprintFunc()
var colorGreen = color.New(color.FgGreen).SprintFunc()

var DeliverTxCounter = uint32(0)
var CheckTxCounter = uint32(0)

func blsSignTx(sk *blst.SecretKey, hash, txdata, dst []byte) []byte {
	sig := new(Signature).Sign(sk, hash, dst).Compress()
	data := append(sig, txdata...)
	return data
}

func UpdateTxHash(source, state, counter []byte) ([]byte, []byte) {
	txdata := append(source, state...)
	hash := hashData(txdata)
	hashdata := append(hash, counter...)
	hash = hashData(hashdata)
	return hash, txdata
}

func batchTxHash(pad byte, source, amount, multisignature, addresses, state, blockheight []byte) ([]byte, []byte) {
	txdata := append(source, amount...)
	txdata = append(txdata, pad)
	txdata = append(txdata, multisignature...)
	txdata = append(txdata, state...)
	txdata = append(txdata, blockheight...)
	txdata = append(txdata, addresses...)
	hash := hashData(txdata)
	return hash, txdata
}

func contractTxHash(pad byte, source, amount, target, payload, counter []byte) ([]byte, []byte) {
	txdata := append(source, amount...)
	txdata = append(txdata, pad)
	txdata = append(txdata, target...)
	txdata = append(txdata, payload...)
	fmt.Println("AMOUNT: ", amount)
	hash := hashData(txdata)
	hashdata := append(hash, counter...)
	hash = hashData(hashdata)
	return hash, txdata
}

func transferUpdateTxHash(source, target, amount, state, counter []byte) ([]byte, []byte) {
	txdata := append(source, target...)
	txdata = append(txdata, amount...)
	txdata = append(txdata, state...)
	hash := hashData(txdata)
	hashdata := append(hash, counter...)
	hash = hashData(hashdata)
	return hash, txdata
}

func transferTxHash(source, target, amount, counter []byte) ([]byte, []byte) {
	txdata := append(source, target...)
	txdata = append(txdata, amount...)
	hash := hashData(txdata)
	hashdata := append(hash, counter...)
	hash = hashData(hashdata)
	return hash, txdata
}

func stakeTxHash(source, amount, counter []byte) ([]byte, []byte) {
	txdata := append(source, amount...)
	hash := hashData(txdata)
	hashdata := append(hash, counter...)
	hash = hashData(hashdata)
	return hash, txdata
}

func releaseTxHash(source, counter []byte) ([]byte, []byte) {
	hash := hashData(source)
	hashdata := append(hash, counter...)
	hash = hashData(hashdata)
	return hash, source
}

func changeAccountKeyTxHash(spubkey, bpubkey, pop, source, counter []byte) ([]byte, []byte) {
	txdata := append(source, spubkey...)
	txdata = append(txdata, bpubkey...)
	//fmt.Println("part:", len(txdata))
	txdata = append(txdata, pop...)
	hash := hashData(txdata)
	hashdata := append(hash, counter...)
	hash = hashData(hashdata)
	return hash, txdata
}

func createAccountTxHash(spubkey, bpubkey, pop, source, amount, counter []byte) ([]byte, []byte) {
	txdata := append(source, amount...)
	txdata = append(txdata, spubkey...)
	txdata = append(txdata, bpubkey...)
	//fmt.Println("part:", len(txdata))
	txdata = append(txdata, pop...)
	hash := hashData(txdata)
	hashdata := append(hash, counter...)
	hash = hashData(hashdata)
	return hash, txdata
}

func prepareContractPayload(payload []byte) byte {
	//if txsize matches one preset size
	// add 1 byte pad to the payload to
	//distinguish it

	txSize := len(payload) + 13

	switch txSize {
	case 100:
	case 68:
	case 72:
	case 74:
	case 76:
	case 108:
	case 244:
	case 248:
	default:
		return 0
	}

	pad := byte(1)
	payload = append(payload, pad)
	return pad
}

func contractTx(privkey crypto.PrivKey, source, amount, target, payload, counter []byte) {
	pad := prepareContractPayload(payload)
	hash, data := contractTxHash(pad, source, amount, target, payload, counter)
	data = signTx(privkey, hash, data)
	sendTx(data)
}

func batchTx(privkey crypto.PrivKey, source, amount, state, blockheight []byte, sigsWithAddrs [][]byte) {
	pad := byte(16)
	var sigArray [][]byte
	var addresses []byte

	var sig Signature
	var dst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")

	extState := append(state, blockheight...)

	for i := 0; i+1 < len(sigsWithAddrs); i += 2 {
		singleSig := sigsWithAddrs[i]
		singleAddr := sigsWithAddrs[i+1]

		accountData := query(singleAddr)
		if len(accountData) < 84 {
			continue
		}

		blsPubKey := accountData[36:84]

		if sig.VerifyCompressed(singleSig, true, blsPubKey, true, extState, dst) {
			sigArray = append(sigArray, singleSig)
			addresses = append(addresses, singleAddr...)
		}
	}
	var agg blst.P2Aggregate
	if !agg.AggregateCompressed(sigArray, true) {
		panic("failed to aggregate signatures")
		return
	}
	aff := agg.ToAffine()
	multisignature := aff.Serialize()

	hash, data := batchTxHash(pad, source, amount, multisignature, addresses, state, blockheight)
	data = signTx(privkey, hash, data)
	sendTx(data)
}

func UpdateTx(privkey crypto.PrivKey, source, state, counter []byte) {
	hash, data := UpdateTxHash(source, state, counter)
	data = signTx(privkey, hash, data)
	sendTx(data)
}

func transferWithUpdateTx(privkey crypto.PrivKey, source, target, amount, state, counter []byte) {
	hash, data := transferUpdateTxHash(source, target, amount, state, counter)
	data = signTx(privkey, hash, data)
	sendTx(data)
}

func transferTx(privkey crypto.PrivKey, source, target, amount, counter []byte) {
	hash, data := transferTxHash(source, target, amount, counter)
	data = signTx(privkey, hash, data)
	sendTx(data)
}

func releaseTx(privkey crypto.PrivKey, source, counter []byte) {
	hash, data := releaseTxHash(source, counter)
	data = signTx(privkey, hash, data)
	sendTx(data)
	//fmt.Println(hash, data)
}

func stakeTx(privkey crypto.PrivKey, source, amount, counter []byte) {
	hash, data := stakeTxHash(source, amount, counter)
	data = signTx(privkey, hash, data)
	sendTx(data)
	//fmt.Println(hash, data)
}

func changeAccountKeyTx(privkey crypto.PrivKey, spubkey, bpubkey, pop, source, counter []byte) *Account {
	hash, data := changeAccountKeyTxHash(spubkey, bpubkey, pop, source, counter)
	account := new(Account)
	account.schnorrPubKey = spubkey
	account.blsPubKey = bpubkey
	account.pop = pop
	account.Data = data[4:88]

	data = signTx(privkey, hash, data)

	//base64Message :=
	sendTx(data)
	//decodedMessage, _ := base64.StdEncoding.DecodeString(string(base64Message))

	account.Address = source
	//decodedMessage

	//mt.Println("all:", len(data))
	return account
}

func createAccountTx(privkey crypto.PrivKey, spubkey, bpubkey, pop, source, amount, counter []byte) *Account {
	hash, data := createAccountTxHash(spubkey, bpubkey, pop, source, amount, counter)

	account := new(Account)
	account.schnorrPubKey = spubkey
	account.blsPubKey = bpubkey
	account.pop = pop
	account.Amount = amount
	account.Data = data[4:92]

	data = signTx(privkey, hash, data)

	base64Message := sendTx(data)
	decodedMessage, _ := base64.StdEncoding.DecodeString(string(base64Message))

	account.Address = decodedMessage

	fmt.Println("account.Address:", account.Address)
	return account
}

func signTx(privkey crypto.PrivKey, hash, txdata []byte) []byte {
	sig2, _ := privkey.Sign(hash)
	data := append(sig2, txdata...)

	fmt.Println("Schnorr signature:")
	fmt.Println(sig2)
	//fmt.Println("Poseidon Hash:")
	fmt.Println(hash)

	return data
}

func sendTx(data []byte) []byte {
	fmt.Println("txsend:")
	// Convert the binary data to a URL-encoded hex string
	fmt.Println("size: ", len(data))
	hexString := hex.EncodeToString(data)
	fmt.Println(hexString)

	escapedTx := url.QueryEscape(hexString)
	url := "http://localhost:26657/broadcast_tx_commit?tx=0x" + escapedTx
	resp, err := http.Get(url)

	if err != nil {
		fmt.Println("ERRRRRRRROR")
		// Handle error
	} else {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error reading response body:", err)
			return nil
		}

		if resp.StatusCode != http.StatusOK {
			fmt.Println("Error: Response status code:", resp.StatusCode)
			//fmt.Println("Response body:", string(body))
			return nil
		}
		fmt.Println("Response body:", string(body))
		res := fromJson(body, "result")
		ctx := fromJsonMap(res, "check_tx")
		dtx := fromJsonMap(res, "deliver_tx")
		dc := fromJsonMap(dtx, "code")
		cc := fromJsonMap(ctx, "code")
		dt := fromJsonMap(dtx, "data")

		xType := fmt.Sprintf("%T", cc)
		fmt.Println("dt", dt, "cc", cc, "dd", dc, xType)
		if cc == float64(0) {
			fmt.Println("CheckTx: ...", colorGreen("OK"))
			CheckTxCounter++
		} else {
			fmt.Println("CheckTx: ...", colorRed("ERROR: "), cc)
		}
		if dc == float64(0) {
			fmt.Println("DeliverTx: ...", colorGreen("OK"))
			DeliverTxCounter++
		} else {
			fmt.Println("DeliverTx: ...", colorRed("ERROR: "), cc)
		}

		resp.Body.Close()
		if dt == nil {
			return nil
		}

		ret := []byte(dt.(string))
		return ret
	}
	return nil
}

func query(data []byte) []byte {
	hexString := hex.EncodeToString(data)
	escapedTx := url.QueryEscape(hexString)
	url := "http://localhost:26657/abci_query?data=0x" + escapedTx
	resp, err := http.Get(url)

	if err != nil {
		fmt.Println("QuERRRRRRRROR", err)
		// Handle error
	} else {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error reading response body:", err)
			return nil
		}

		if resp.StatusCode != http.StatusOK {
			fmt.Println("Error: Response status code:", resp.StatusCode)
			return nil
		}
		//fmt.Println("Response body:", string(body))
		res := fromJson(body, "result")
		rsp := fromJsonMap(res, "response")
		vl := fromJsonMap(rsp, "value")
		//fmt.Println("value:", vl)
		resp.Body.Close()

		// vl is the variable of type interface{}
		if encoded, ok := vl.(string); ok {
			// vl is of type []byte, do something with it
			// Decode the string to binary data
			//encoded = encoded[:len(encoded)-4]
			//fmt.Println(len(encoded), encoded)
			//encoded = strings.TrimRight(encoded, "=")
			for len(encoded)%4 != 0 {
				encoded += "="
			}

			bytes, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				panic(err)
			}
			return bytes
		} else {
			// vl is not of type []byte, handle the error
			return nil // or return an error, log, etc.
		}
	}
	return nil
}

// Function to create a new account from scratch and fund it using a source account's address and secret
func createNewAccountTx(sourceAddress, counter, amount, sourceSecret []byte) (*Account, []byte, error) {
	// Restore keys for the source account using the provided secret
	sprivkey, _, _, _, _, err := generateKeysFromSecret(sourceSecret, nil, nil)
	if err != nil {
		return nil, nil, err
	}

	// Generate random keys for the new account
	newSecret, _, spubkey, blspk, pop, _, err := generateRandomKeys(sourceAddress, counter)
	if err != nil {
		return nil, nil, err
	}

	// Create the source account and transfer funds to the new account
	newAccount := createAccountTx(sprivkey, spubkey.Bytes(), blspk, pop, sourceAddress, amount, counter)
	newAccount.secret = newSecret

	return newAccount, newSecret, nil
}

func autoChangeAccountKeysTx(sourceAddress, counter, sourceSecret []byte) (*Account, []byte, error) {

	// Restore keys for the source account using the provided secret
	sprivkey, _, _, _, _, err := generateKeysFromSecret(sourceSecret, nil, nil)
	if err != nil {
		return nil, nil, err
	}

	// Generate random keys for the new account
	newSecret, _, spubkey, blspk, pop, _, err := generateRandomKeys(sourceAddress, counter)
	if err != nil {
		return nil, nil, err
	}

	// Create the source account and transfer funds to the new account
	newAccount := changeAccountKeyTx(sprivkey, spubkey.Bytes(), blspk, pop, sourceAddress, counter)

	return newAccount, newSecret, nil
}
