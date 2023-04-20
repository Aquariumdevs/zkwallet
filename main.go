package main


import (
        "crypto/sha256"
        blst "github.com/supranational/blst/bindings/go"
        //abcitypes "github.com/tendermint/tendermint/abci/types"
        //"bytes"
        "fmt"
	"os"
	"strings"
        "crypto/rand"
        //"wallet/poseidon"
        //"github.com/syndtr/goleveldb/leveldb"
        //"strconv"
        //"encoding/binary"
        //"math/big"
	//"golang.org/x/
	"encoding/base64"
	"github.com/tendermint/tendermint/crypto/ed25519"
	"github.com/tendermint/tendermint/crypto"
	"net/http"
	"net/url"
	"io/ioutil"
	"encoding/json"
	"encoding/hex"
	"github.com/hbakhtiyor/schnorr"
	"math/big"
	"wallet/poseidon"
	"github.com/vocdoni/arbo"
)

type Account struct {      
        Address []byte        
        Data []byte         
	schnorrPubKey []byte       
	blsPubKey []byte 
	pop []byte 
        counter []byte   
	Amount  []byte        
}

type PublicKey = blst.P1Affine             
type PrivateKey = blst.P1Affine             
type Signature = blst.P2Affine             
type AggregateSignature = blst.P2Aggregate 
type AggregatePublicKey = blst.P1Aggregate 

func hashData(data []byte) ([]byte) {                                
        h2, _ := poseidon.HashBytes(data)
	
	result := arbo.BigIntToBytes(32, h2)                  
	return result                                 
}

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
		fmt.Println(skm,sk,pk,msg)
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

func blsKeyPair(secret, source, counter []byte) (blst.SecretKey, PublicKey, []byte, []byte, []byte) {
	//Bls from seed
	fmt.Println("Bls from seed:")
	
	var dst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")                     
	

        sk := blst.KeyGen(secret)

        pk := new(PublicKey).From(sk)

	blspk := pk.Compress()
	
	
	//proof of possesion
	h := sha256.New()    
	h.Write(blspk)   
	h.Write(source)
	h.Write(counter)                      
	sha2 := h.Sum(nil)
	
	sig := new(Signature).Sign(sk, sha2, dst)
	pop := sig.Compress()
	
	fmt.Println("____", source, counter)
	fmt.Println("Hash: ", sha2)
	fmt.Println("POP: ", pop)                            
        fmt.Println("BLSPK: ", blspk)
	
	//fmt.Println(blspk, len(blspk), sha2, pop, len(pop))
	blsCompressedVerify(sig, pop, blspk, sha2, dst)
	return *sk, *pk, blspk, pop, dst
}	


func blsSignTx(sk *blst.SecretKey, hash, txdata, dst []byte) []byte {	
        sig := new(Signature).Sign(sk, hash, dst).Compress()
	data := append(sig, txdata...)
	return data
}	
	
func blsCompressedVerify(sig *Signature, sg, blspk, msg, dst []byte) bool {
        if sig.VerifyCompressed(sg, false, blspk, true, msg, dst) {
		fmt.Println("Pop Valid!")
		return true
	} else {
		fmt.Println("fuck")
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

func bls(sk PrivateKey, hash, data, dst []byte) {	
	
}

func stests() {
	//scnorr64b rnd
	fmt.Println("scnorr64 rnd")
	
        msg := []byte("hello foo")
	
	privkey1 := ed25519.GenPrivKey() 
	pubkey := privkey1.PubKey()
	sig2, _ := privkey1.Sign(msg)
	
	if !pubkey.VerifySignature( msg, sig2) {
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

        if !pubkey.VerifySignature( msg, sig2) {
                fmt.Println("ERROR: Invalid!")
        } else {
                fmt.Println("Valid!")
                //fmt.Println(privkey,pubkey,msg)
        }
}

func UpdateTxHash(source, state, counter []byte) ([]byte, []byte) { 
        txdata := append(source, state...)
        hash := hashData(txdata)
        hashdata := append(hash, counter...)
        hash = hashData(hashdata)
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
	
func changeAccountKeyTxHash(spubkey, bpubkey, pop,  source, counter []byte) ([]byte, []byte) {
        txdata := append(source, spubkey...)
        txdata = append(txdata, bpubkey...)
        //fmt.Println("part:", len(txdata))
        txdata = append(txdata, pop...)
        hash := hashData(txdata)
        hashdata := append(hash, counter...)
        hash = hashData(hashdata)
        return hash, txdata
}

func createAccountTxHash(spubkey, bpubkey, pop,  source, amount, counter []byte) ([]byte, []byte) {        
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

func UpdateTx(privkey crypto.PrivKey, source, state, counter []byte) {
        hash, data := UpdateTxHash(source, state, counter)
        data = signTx(privkey, hash, data)
        sendTx(data)
}

func transferWithUpdateTx(privkey crypto.PrivKey, source, target, amount, state, counter []byte) {      
        hash, data :=transferUpdateTxHash(source, target, amount, state, counter)                   
        data = signTx(privkey, hash, data)                                             
        sendTx(data)                                                                   
}

func transferTx(privkey crypto.PrivKey, source, target, amount, counter []byte) {
	hash, data :=transferTxHash(source, target, amount, counter)
	data = signTx(privkey, hash, data)
	sendTx(data)	
}

func releaseTx(privkey crypto.PrivKey, source, counter []byte) {
        hash, data :=releaseTxHash(source, counter)
        data = signTx(privkey, hash, data) 
	sendTx(data)                                          
	//fmt.Println(hash, data)                      
}

func stakeTx(privkey crypto.PrivKey, source, amount, counter []byte) {
        hash, data :=stakeTxHash(source, amount, counter) 
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
	
        account.Address = sendTx(data)
	
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
	
	account.Address = sendTx(data)   
	 
	//mt.Println("all:", len(data))                                                   
	return account
}

func signTx(privkey crypto.PrivKey, hash, txdata []byte) []byte {
	sig2, _ := privkey.Sign(hash)
	data := append(sig2, txdata...)
	
	fmt.Println("Schnorr signature:")
	fmt.Println(sig2)
	fmt.Println("Poseidon Hash:")
	fmt.Println(hash)
	
	return data
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
		dtx := fromJsonMap(res, "deliver_tx")
		dt := fromJsonMap(dtx, "data")

		fmt.Println("dt", dt)
		
	 	resp.Body.Close()		
		if dt == nil {
			return nil
		}
		
		ret := []byte(dt.(string))
		return ret
	}
	return nil
}

func  fromJsonMap(body interface{}, data string) interface{} {
	if body != nil {
		return body.(map[string]interface{})[data]
	} else {
		return nil
	}
}

func  fromJson(body []byte, data string) interface{} {
	//fmt.Println("Response body:", string(body))
	m := make(map[string]interface{})
	if body == nil {
		return nil
	}
	err := json.Unmarshal(body, &m)
	if err != nil {
		return nil
	}
	dt := m[data]
	return dt
}

func query(data []byte) interface{} {
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
		fmt.Println("Response body:", string(body))
		res := fromJson(body, "result")
		rsp := fromJsonMap(res, "response")
		vl := fromJsonMap(rsp, "value")
		fmt.Println("value:", vl)
 		resp.Body.Close()
		return vl
	}
	return nil
}

func test() {
	//ftests()
	//stests()
	secret:= []byte("Iloveyou!")
	source := []byte{0,0,0,0}
	target := []byte{0,0,0,1}
	amount := []byte{0,5,0,0}
	
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
	amount = []byte{0,0,0,1}

	counter = []byte{0, 0, 0, 1}
	transferWithUpdateTx(sprivkey, source, target, amount, ikm[:], counter)	

	if account.Address == nil {
		fmt.Println("nil data. Querying...")
		query(account.blsPubKey)
	}
	q := query(account.blsPubKey)
	fmt.Println("Query tx by pk: ", q)
	fmt.Println("Query tx by address...")
	
	Val, ok := q.(string)
	if ok {
		decoded, err := base64.StdEncoding.DecodeString(Val)
		if err != nil {
			fmt.Println("Error decoding base64 string:", err)
			return
		}
		fmt.Println(decoded)
		q = query(decoded)
	}
	
	Val, ok = q.(string)                                                          
        if ok {                                                                        
                decoded, _ := base64.StdEncoding.DecodeString(Val)
		fmt.Println("decoded: ", decoded, " of length: ", len(decoded))
	}
	
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

func encodeHexResults(results [][]byte) (string, error) {
    var encoded []string
    for _, result := range results {
        encodedArg := hex.EncodeToString(result)
        encoded = append(encoded, encodedArg)
    }
    return strings.Join(encoded, " "), nil
}


func decodeHexArgs(args ...string) ([][]byte, error) {
	var decoded [][]byte
	for _, arg := range args {
		decodedArg, err := hex.DecodeString(arg)
		if err != nil {
			return nil, fmt.Errorf("error decoding %s: %w", arg, err)
		}
		decoded = append(decoded, decodedArg)
	}
	return decoded, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: wallet <function> <arg1> <arg2> ...")
		os.Exit(1)
	}

	function := os.Args[1]
	args := os.Args[2:]
	
	var decodedArgs [][]byte
	var err error
	switch function {
	case "test":
        	if len(args) != 0 {
            		fmt.Println("Usage: wallet test")
			os.Exit(1)
		}
	case "ftest":
        	if len(args) != 0 {
            		fmt.Println("Usage: wallet ftest")
			os.Exit(1)
		}
        case "stest":
        	if len(args) != 0 {
            		fmt.Println("Usage: wallet stest")
			os.Exit(1)
		}
	case "createKeys":
        	if len(args) != 2 {
            		fmt.Println("Usage: wallet createKeys <source> <counter>")
			os.Exit(1)
		}
	case "createAccountTx":
		if len(args) != 7 {
			fmt.Println("Usage: wallet createAccountTx <secret> <spubkey> <blspk> <pop> <source> <target> <amount> <counter>")
			os.Exit(1)
		}
    	case "transferWithUpdateTx":
        	if len(args) != 6 {
        	    	fmt.Println("Usage: wallet transferWithUpdateTx <secret> <source> <target> <amount> <statehash> <counter>")
            		os.Exit(1)
        	}
    	case "query":
        	if len(args) != 1 {
            		fmt.Println("Usage: wallet query <pk>/<address>/<address+counter>")
            		os.Exit(1)
        	}
    	case "transferTx":
        	if len(args) != 4 {
            		fmt.Println("Usage: wallet transferTx <secret> <source> <target> <amount>")
            		os.Exit(1)
        	}
    	case "UpdateTx":
        	if len(args) != 3 {
            		fmt.Println("Usage: wallet UpdateTx <secret> <source> <statehash>")
            		os.Exit(1)
        	}
    	case "changeAccountKeyTx":
        	if len(args) != 6 {
            		fmt.Println("Usage: wallet changeAccountKeyTx <secret> <spubkey> <blspk> <pop> <source> <counter>")
            		os.Exit(1)
        	}
    	case "stakeTx":
        	if len(args) != 4 {
            		fmt.Println("Usage: wallet stakeTx <secret> <source> <amount> <counter>")
            		os.Exit(1)
        	}
	case "releaseTx":
        	if len(args) != 3 {
            		fmt.Println("Usage: wallet stakeTx <secret> <source> <amount> <counter>")
			os.Exit(1)
		}
	case "contractTx":
	       	if len(args) != 6 {
            		fmt.Println("Usage: wallet contractTx <secret> <source> <amount> <target> <payload> <counter>")
			os.Exit(1)
		}
	default:
		fmt.Println("Unknown function:", function)
		os.Exit(1)
	}
	
	decodedArgs, err = decodeHexArgs(args...)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	switch function {
	case "test":
		test()
	case "ftest":
		ftests()
	case "stest":
		stests()
	case "createKeys":
    		source := decodedArgs[0]
    		counter := decodedArgs[1]
		secret := make([]byte, 32)
    		// read random data into the buffer
   		 _, err := rand.Read(secret)
    		if err != nil {
        		panic(err)
    		}
		sprivkey, spubkey := sKeyPair(secret)
    		_, _, blspk, pop, dst := blsKeyPair(secret, source, counter)
		str, err := encodeHexResults([][]byte{secret, sprivkey.Bytes(), spubkey.Bytes(), blspk, pop, dst})
		if err != nil {
			panic(err)
		}
		fmt.Println(str)
	case "createAccountTx":
    		secret := decodedArgs[0]
    		sprivkey, _ := sKeyPair(secret)
		spubkey := decodedArgs[1]
		blspk := decodedArgs[2]
		pop := decodedArgs[3]
    		source := decodedArgs[4]
    		amount := decodedArgs[5]
    		counter := decodedArgs[6]
    		account := createAccountTx(sprivkey, spubkey, blspk, pop, source, amount, counter)
    		fmt.Println(account)
	case "transferWithUpdateTx":
    		secret := decodedArgs[0]
    		source := decodedArgs[1]
    		target := decodedArgs[2]
    		amount := decodedArgs[3]
    		statehash := decodedArgs[4]
    		counter := decodedArgs[5]
		sprivkey, _ := sKeyPair(secret)
    		transferWithUpdateTx(sprivkey, source, target, amount, statehash, counter)
	case "query":
    		dat := decodedArgs[0]
    		q := query(dat)
    		fmt.Println(q)
	case "transferTx":
    		secret := decodedArgs[0]
    		source := decodedArgs[1]
    		target := decodedArgs[2]
    		amount := decodedArgs[3]
    		counter := decodedArgs[4]
		sprivkey, _ := sKeyPair(secret)
    		transferTx(sprivkey, source, target, amount, counter)
	case "UpdateTx":
    		secret := decodedArgs[0]
    		source := decodedArgs[1]
    		statehash := decodedArgs[2]
    		counter := decodedArgs[3]
		sprivkey, _ := sKeyPair(secret)
    		UpdateTx(sprivkey, source, statehash, counter)
	case "changeAccountKeyTx":
    		secret := decodedArgs[0]
    		spubkey := decodedArgs[1]
    		blspk := decodedArgs[2]
    		pop := decodedArgs[3]
    		source := decodedArgs[4]
    		counter := decodedArgs[5]
		sprivkey, _ := sKeyPair(secret)
    		changeAccountKeyTx(sprivkey, spubkey, blspk, pop, source, counter)
	case "stakeTx":
    		secret := decodedArgs[0]
    		source := decodedArgs[1]
    		amount := decodedArgs[2]
    		counter := decodedArgs[3]
		sprivkey, _ := sKeyPair(secret)
    		stakeTx(sprivkey, source, amount, counter)
	case "releaseTx":  
		secret := decodedArgs[0]
		source := decodedArgs[1]
                counter := decodedArgs[2]
		sprivkey, _ := sKeyPair(secret)
                releaseTx(sprivkey, source, counter)
	case "contractTx":
		secret := decodedArgs[0]
    		source := decodedArgs[1]
    		amount := decodedArgs[2]
    		target := decodedArgs[3]
    		payload := decodedArgs[4]
	    	counter := decodedArgs[5]
		sprivkey, _ := sKeyPair(secret)
    		contractTx(sprivkey, source, amount, target, payload, counter)

	default:
		fmt.Println("Unknown function:", function)
		os.Exit(1)
	}
}


 
