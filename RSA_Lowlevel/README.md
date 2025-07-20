# Low-Level RSA Implementation of RSA Encryption and Digital Signature using Number-Theoretic Primitives (Crypto++ Library)

## RSA key generation
g++ keygen.cpp -o rsa_keygen_manual -lcryptopp && ./rsa_keygen_manual

## Encrypt
g++ encrypt.cpp -o encrypt -lcryptopp && ./encrypt public_key.bin msg.txt

## Decryption
g++ decrypt.cpp -o decrypt -lcryptopp && ./decrypt private_key.bin cipher.bin

## Signs
g++ sign.cpp -o sign -lcryptopp && ./sign private_key.bin msg.txt

## Verify
g++ verify.cpp -o verify -lcryptopp && ./verify public_key.bin dec_msg.txt sign.bin