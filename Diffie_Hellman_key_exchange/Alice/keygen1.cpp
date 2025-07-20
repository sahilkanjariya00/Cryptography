#include <iostream>
#include <cryptopp/dh.h>
#include <cryptopp/osrng.h>
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h> // For GCD
#include <cryptopp/secblock.h> 
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/algparam.h>
#include <cryptopp/dh2.h>

using namespace CryptoPP;
using namespace std;

// Function to check if two numbers are coprime
bool AreCoprime(const Integer& a, const Integer& b) {
    return (GCD(a, b) == Integer::One());
}

int main() {
    // Auto-seeded random number generator
    AutoSeededRandomPool rng;

    // Use predefined p and g from RFC 3526 (1024-bit group)
    Integer p("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
              "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
              "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E"
              "7EC6F44C42E9A63A36210000000000090563");
    Integer g("2");

    cout << "Prime (p): " << std::hex << p << endl;
    cout << "Generator (g): " << std::hex << g << endl;

    // Ensure private key is coprime with p-1
    Integer pMinus1 = p - 1;
    Integer privateKey;
    
    do {
        privateKey.Randomize(rng, Integer::One(), pMinus1); // Generate a random private key
    } while (!AreCoprime(privateKey, pMinus1)); // Repeat until privateKey is coprime to p-1

    cout << "Private Key: " << std::hex << privateKey << endl;

    // Generate public key: public_key = g^private_key mod p
    Integer publicKey = a_exp_b_mod_c(g, privateKey, p);

    cout << "Public Key: " << std::hex << publicKey << endl;

    // Save the keys to files
    FileSink("private_key.bin").Put(reinterpret_cast<const byte*>(&privateKey), privateKey.MinEncodedSize());
    FileSink("public_key.bin").Put(reinterpret_cast<const byte*>(&publicKey), publicKey.MinEncodedSize());
    
    return 0;
}
