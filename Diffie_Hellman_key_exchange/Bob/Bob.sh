#!/bin/bash

g++ -o keygen1 keygen1.cpp -lcryptopp -std=c++11 && ./keygen1

SERVER_IP="10.0.2.15"  # Server's IP address
PORT=22222
PUBLIC_KEY_FILE="public_key.bin"
RECEIVED_PUBLIC_KEY_FILE="received_public_key.bin"

echo "Sending Bob's public key to Alice at $SERVER_IP on port $PORT..."

# Bob sends his public key first
nc -v $SERVER_IP $PORT < $PUBLIC_KEY_FILE

# Bob waits to receive Alice's public key
echo "Waiting to receive Alice's public key..."
nc -v -l -p $PORT -w 5 > $RECEIVED_PUBLIC_KEY_FILE

echo "Public key received from Alice."

# Calculate g^xy (shared secret)
g++ -o calculate_gxy calculate_gxy.cpp -lcryptopp -std=c++11
gxy=$(./calculate_gxy private_key.bin received_public_key.bin)
echo $gxy
echo -n $gxy | xxd -r -p > gxy_key.bin

echo "g^xy saved to gxy_key.bin"
