package main

import (
	"fmt"
	"os"
)

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
	case "testcna":
		if len(args) != 0 {
			fmt.Println("Usage: wallet testcna")
			os.Exit(1)
		}
	case "testrnd":
		if len(args) != 0 {
			fmt.Println("Usage: wallet testrnd")
			os.Exit(1)
		}
	case "createKeys":
		if len(args) != 2 {
			fmt.Println("Usage: wallet createKeys <source> <counter>")
			os.Exit(1)
		}
	case "createAccountTx":
		if len(args) != 7 {
			fmt.Println("Usage: wallet createAccountTx <secret> <spubkey> <blspk> <pop> <source> <amount> <counter>")
			os.Exit(1)
		}
	case "createNewAccountTx":
		if len(args) != 4 {
			fmt.Println("Usage: wallet createNewAccountTx <secret> <source> <amount> <counter>")
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
		if len(args) != 5 {
			fmt.Println("Usage: wallet transferTx <secret> <source> <target> <amount> <counter>")
			os.Exit(1)
		}
	case "UpdateTx":
		if len(args) != 4 {
			fmt.Println("Usage: wallet UpdateTx <secret> <source> <statehash> <counter>")
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
	case "batchTx":
		if len(args) < 7 || len(args)%2 == 0 {
			fmt.Println("Usage: wallet contractTx <secret> <source> <amount> <state> <blockheight> <signature_1> <address_1> <signature_2> <address_2> ... <signature_n> <address_n>")
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
	case "testcna":
		TestCreateNewAccounts()
	case "testrnd":
		TestRandomOperations()
	case "createKeys":
		source := decodedArgs[0]
		counter := decodedArgs[1]
		secret, sprivkey, spubkey, blspk, pop, dst, nil := generateRandomKeys(source, counter)
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
	case "createNewAccountTx":
		secret := decodedArgs[0]
		source := decodedArgs[1]
		amount := decodedArgs[2]
		counter := decodedArgs[3]
		newaccount, newsecret, err := createNewAccountTx(secret, source, amount, counter)
		fmt.Println(newaccount, newsecret, err)
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
	case "batchTx":
		secret := decodedArgs[0]
		source := decodedArgs[1]
		amount := decodedArgs[2]
		state := decodedArgs[3]
		blockheight := decodedArgs[4]
		sprivkey, _ := sKeyPair(secret)
		sigsWithAddresses := decodedArgs[5:]
		batchTx(sprivkey, source, amount, state, blockheight, sigsWithAddresses)

	default:
		fmt.Println("Unknown function:", function)
		os.Exit(1)
	}
}
