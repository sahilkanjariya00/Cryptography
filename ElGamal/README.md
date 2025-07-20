## Comprehensive Implementation of ElGamal Cryptosystem: Encryption, Decryption, Signing, and Verification

## ElGamal key generation
g++ -o keygen keygen.cpp -lcryptopp -std=c++11 && ./keygen

## Encryption
g++ -o encrypt encrypt.cpp -lcryptopp -std=c++11 && ./encrypt public_key.bin data.txt

## Decryption
g++ -o decrypt decrypt.cpp -lcryptopp -std=c++11 && ./decrypt private_key.bin cipher.bin

## Signature
g++ -o signature signature.cpp -lcryptopp -std=c++11 && ./signature private_key.bin data.txt

## Signature Verification
g++ -o verify verify.cpp -lcryptopp -std=c++11 && ./verify public_key.bin dtext.txt signature.bin