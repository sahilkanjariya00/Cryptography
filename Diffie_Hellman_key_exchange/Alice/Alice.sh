#!/bin/bash

g++ -o keygen1 keygen1.cpp -lcryptopp -std=c++11 && ./keygen1

PORT=22222
PUBLIC_KEY_FILE="public_key.bin"
RECEIVED_PUBLIC_KEY_FILE="received_public_key.bin"
BOB_IP="10.0.2.15"

echo "Waiting for Bob's public key on port $PORT..."

# Alice first receives Bob's public key and captures connection details (including Bob's dynamic port and IP)
# Redirecting stderr (2) to a file to capture the connection info
nc -v -l -p $PORT -w 5 > $RECEIVED_PUBLIC_KEY_FILE 2> connection_info.txt
echo "Public key received from Bob."

# Read the connection info from the file
connection_info=$(cat connection_info.txt)
echo "Connection info: $connection_info"

# Extract Bob's dynamic port from the connection info
# BOB_PORT=$(echo "$connection_info" | grep -oP 'Connection received on \S+ \K\d+')
# # Extract Bob's IP address from the connection info
# BOB_IP=$(echo "$connection_info" | grep -oP 'Connection received on \K\S+')

# if [ -z "$BOB_PORT" ] || [ -z "$BOB_IP" ]; then
#     echo "Failed to extract Bob's port number or IP address."
#     exit 1
# fi

# echo "Bob's IP address is $BOB_IP"
# echo "Bob's dynamic port is $BOB_PORT"

# Alice sends her public key to Bob on Bob's dynamic port and IP address
echo "Sending Alice's public key to Bob at $BOB_IP on port $BOB_PORT..."
nc -v $BOB_IP $BOB_PORT < $PUBLIC_KEY_FILE

# Compile and calculate g^xy (shared secret)
g++ -o calculate_gxy calculate_gxy.cpp -lcryptopp -std=c++11
gxy=$(./calculate_gxy private_key.bin received_public_key.bin)
echo "g^xy: $gxy"
echo -n $gxy | xxd -r -p > gxy_key.bin

echo "g^xy saved to gxy_key.bin"


