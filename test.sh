#!/bin/bash

# Initialize an array to store created accounts
declare -a accounts

# Function to create an account and transfer funds to it
create_account() {
    secret="$1"
    source_account="$2"
    amount="$3"

    # Create a new account and store the result in a variable
    result=$(./wallet createAccountTx "$secret" "$source_account" "$amount" "1")

    # Check if the result is valid (assuming it returns the new account address)
    #if [[ "$result" =~ ^[0-9a-f]+$ ]]; then
    #    accounts+=("$result")  # Add the new account address to the array
    #else
    #    echo "Failed to create account with secret: $secret"
    #fi
}

# Initial account with address = 0 and secret="Iloveyou!"
initial_secret="Iloveyou!"
source_account=0
amount="1000"  # Initial amount of funds

# Create the initial account
#create_account "$initial_secret" "$source_account" "$amount"

# Create additional accounts and transfer funds between them
# You can customize the number of accounts and transfer amounts as needed
for i in {1..5}; do
    secret="Secret$i"  # Replace with your desired secret for the new account
    source_account="${accounts[$((i - 1))]}"  # Use the previous account as the source

    # Create the new account and transfer funds from the source account
    create_account "$secret" "$source_account" "$amount"
done

# Print the addresses of all created accounts
echo "Created accounts:"
for account in "${accounts[@]}"; do
    echo "$account"
done
