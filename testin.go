package main

import (
	"fmt"
	"math/rand"
	"time"
)

var testTxCounter = uint32(0)

func TestCreateNewAccounts() []*Account {

	// Initialize the template account
	templateAddress := []byte{0, 0, 0, 0} // Address for the template account
	initialAmount := []byte{0, 250, 0, 0} // Initial amount of funds
	templateSecret := []byte("Iloveyou!")

	templateAccount := new(Account)
	templateAccount.Address = templateAddress
	templateAccount.Amount = initialAmount
	templateAccount.counter = []byte{0, 0, 0, 0}
	templateAccount.secret = templateSecret

	// Store the template account in an array
	accounts := []*Account{templateAccount}

	// Create additional accounts and transfer funds on them
	Amount := initialAmount
	for i := 1; i <= 20; i++ {
		testTxCounter++

		sourceAccount := accounts[i-1]

		decrement(Amount, 10*256*256)
		newAccount := TestCreateNewAccount(sourceAccount, Amount)
		accounts[i-1].counter = []byte{0, 0, 0, 1}

		// Store the new account
		accounts = append(accounts, newAccount)
		//printAccounts(accounts)
	}
	return accounts
}

func TestCreateNewAccount(sourceAccount *Account, Amount []byte) *Account {
	// Create the new account and transfer funds from the source account
	newAccount, newSecret, err := createNewAccountTx(sourceAccount.Address, sourceAccount.counter, Amount, sourceAccount.secret)
	if err != nil {
		fmt.Println("error: ", err)
		//t.Fatalf("Failed to create account %d: %v", i, err)
	}
	// Store the new secret
	newAccount.secret = newSecret
	newAccount.counter = []byte{0, 0, 0, 0}

	return newAccount
}

// Available operations
const (
	TransferOperation           = "transferTx"
	UpdateOperation             = "UpdateTx"
	KeyChangeOperation          = "changeAccountKeyTx"
	AccountCreateOperation      = "createAccountTx"
	transferWithUpdateOperation = "transferWithUpdateTx"
	stakeOperation              = "stakeTx"
	stakeReleaseOperation       = "stakeReleaseTx"
	contractOperation           = "contractTx"
)

func TestRandomOperations() {

	accounts := TestCreateNewAccounts()

	miniAmount := []byte{0, 0, 0, 1}
	initAmount := []byte{0, 5, 0, 0}

	// Initialize the random number generator
	rand.Seed(time.Now().UnixNano())

	// Perform random operations using randomly selected accounts
	for i := 0; i < 30; i++ { // Perform 20 random operations
		// Randomly select an account from the list
		sourceAccount := getRandomAccount(accounts)

		// Randomly select an operation
		operation := getRandomOperation()

		// Perform the selected operation
		switch operation {
		case AccountCreateOperation:
			newAccount := TestCreateNewAccount(sourceAccount, initAmount)
			decrement(initAmount, 256*256)
			// Store the new account
			accounts = append(accounts, newAccount)

		case TransferOperation:
			// Generate random target for transfer
			targetAccount := accounts[rand.Intn(len(accounts))]
			// Generate keys from secret
			sprivkey, _ := sKeyPair(sourceAccount.secret)
			transferTx(sprivkey, sourceAccount.Address, targetAccount.Address, miniAmount, sourceAccount.counter)

		case UpdateOperation:
			// Generate random statehash
			statehash := getRandomStateHash()
			// Generate keys from secret
			sprivkey, _ := sKeyPair(sourceAccount.secret)
			UpdateTx(sprivkey, sourceAccount.Address, statehash, sourceAccount.counter)

		case transferWithUpdateOperation:
			// Generate random target for transfer
			targetAccount := accounts[rand.Intn(len(accounts))]
			// Generate random statehash
			statehash := getRandomStateHash()
			// Generate keys from secret
			sprivkey, _ := sKeyPair(sourceAccount.secret)
			transferWithUpdateTx(sprivkey, sourceAccount.Address, targetAccount.Address, miniAmount, statehash, sourceAccount.counter)

		case KeyChangeOperation:
			cnt := sourceAccount.counter //save the current state of the counter
			sourceAccount, sourceAccount.secret, _ = autoChangeAccountKeysTx(sourceAccount.Address, sourceAccount.counter, sourceAccount.secret)
			sourceAccount.counter = cnt //recover the counter state

		case stakeOperation:
			// Generate keys from secret
			sprivkey, _ := sKeyPair(sourceAccount.secret)
			stakeTx(sprivkey, sourceAccount.Address, miniAmount, sourceAccount.counter)

		case stakeReleaseOperation:
			// Generate keys from secret
			sprivkey, _ := sKeyPair(sourceAccount.secret)
			stakeTx(sprivkey, sourceAccount.Address, miniAmount, sourceAccount.counter)
			//increment counters
			increment(sourceAccount.counter, 1)
			testTxCounter++
			// Wait for 3 seconds
			time.Sleep(3 * time.Second)
			releaseTx(sprivkey, sourceAccount.Address, sourceAccount.counter)

		case contractOperation:
			// Generate random target for transfer
			targetAccount := accounts[rand.Intn(len(accounts))]
			// Generate random payload
			payload := getRandomPayload()

			// Generate keys from secret
			sprivkey, _ := sKeyPair(sourceAccount.secret)
			contractTx(sprivkey, sourceAccount.Address, miniAmount, targetAccount.Address, payload, sourceAccount.counter)
		}

		//increment counters
		increment(sourceAccount.counter, 1)
		testTxCounter++

	}

	if DeliverTxCounter == testTxCounter {
		if CheckTxCounter == testTxCounter {
			fmt.Println(colorGreen("ALL TESTS PASSED SUCCESSFULLY"))
		} else {
			fmt.Println(colorRed(testTxCounter-CheckTxCounter, " CHECKTX TESTS FAILED"))
		}
	} else {
		fmt.Println(colorRed(testTxCounter-DeliverTxCounter, " DELIVERTX TESTS FAILED"))
	}

}

func getRandomAccount(accounts []*Account) *Account {
	if len(accounts) == 0 {
		return nil
	}

	// Select a random index
	randomIndex := rand.Intn(len(accounts))

	// Get the selected account
	selectedAccount := accounts[randomIndex]

	return selectedAccount
}

func printAccounts(accounts []*Account) {
	for _, account := range accounts {
		fmt.Println("Address:", account.Address)
		fmt.Println("Data:", account.Data)
		fmt.Println("SchnorrPubKey:", account.schnorrPubKey)
		fmt.Println("BLSPubKey:", account.blsPubKey)
		fmt.Println("POP:", account.pop)
		fmt.Println("Counter:", account.counter)
		fmt.Println("Amount:", account.Amount)
		fmt.Println("Secret:", account.secret)
		fmt.Println("---------------------------------------")
	}
}

func getRandomOperation() string {
	// Define the available operations
	operations := []string{
		AccountCreateOperation,
		TransferOperation,
		UpdateOperation,
		transferWithUpdateOperation,
		KeyChangeOperation,
		stakeOperation,
		stakeReleaseOperation,
		contractOperation,
	}

	// Randomly select an operation
	return operations[rand.Intn(len(operations))]
}

func getRandomStateHash() []byte {
	// Generate a random statehash
	statehash := make([]byte, 32)
	rand.Read(statehash)
	return statehash
}

func getRandomPayload() []byte {
	rnd := rand.Intn(1000)
	// Generate a random payload (random bytes)
	payload := make([]byte, rnd)
	rand.Read(payload)
	return payload
}

func getRandomPublicKey() []byte {
	// Generate a random public key (32 bytes)
	publicKey := make([]byte, 32)
	rand.Read(publicKey)
	return publicKey
}

func getRandomBLSPublicKey() []byte {
	// Generate a random BLS public key (32 bytes)
	blsPublicKey := make([]byte, 32)
	rand.Read(blsPublicKey)
	return blsPublicKey
}

func getRandomPOP() []byte {
	// Generate a random Proof of Possession (POP, 32 bytes)
	pop := make([]byte, 32)
	rand.Read(pop)
	return pop
}

///////TODO LIST

//query to find initial info
//batch tx
