package main

type Account struct {
	secret        []byte
	Address       []byte
	Data          []byte
	schnorrPubKey []byte
	blsPubKey     []byte
	pop           []byte
	counter       []byte
	Amount        []byte
}

func initAccount(templateAccount *Account) *Account {

	// Create a new account
	newAccount := &Account{
		secret:        make([]byte, len(templateAccount.secret)),
		Address:       make([]byte, len(templateAccount.Address)),
		Data:          make([]byte, len(templateAccount.Data)),
		schnorrPubKey: make([]byte, len(templateAccount.schnorrPubKey)),
		blsPubKey:     make([]byte, len(templateAccount.blsPubKey)),
		pop:           make([]byte, len(templateAccount.pop)),
		counter:       make([]byte, len(templateAccount.counter)),
		Amount:        make([]byte, len(templateAccount.Amount)),
	}

	return newAccount
}

func copyAccount(selectedAccount *Account) *Account {

	// Create a new account
	copiedAccount := initAccount(selectedAccount)

	// copy the data
	copy(copiedAccount.secret, selectedAccount.secret)
	copy(copiedAccount.Address, selectedAccount.Address)
	copy(copiedAccount.Data, selectedAccount.Data)
	copy(copiedAccount.schnorrPubKey, selectedAccount.schnorrPubKey)
	copy(copiedAccount.blsPubKey, selectedAccount.blsPubKey)
	copy(copiedAccount.pop, selectedAccount.pop)
	copy(copiedAccount.counter, selectedAccount.counter)
	copy(copiedAccount.Amount, selectedAccount.Amount)

	return copiedAccount
}
