#include <iostream>
#include <fstream>
#include <crypto++/osrng.h>
#include <crypto++/dh.h>
#include <crypto++/nbtheory.h>
#include <crypto++/integer.h>
#include <crypto++/secblock.h>
#include <crypto++/hex.h>
#include <crypto++/files.h>
#include <crypto++/prime.h>

using namespace CryptoPP;
using namespace std;

int main() {
    // Step 1: Prime and Generator generation using PrimeAndGenerator class
    PrimeAndGenerator pg;
    pg.Generate(1, 128, AutoSeededRandomPool());

    Integer p = pg.Prime();
    Integer g = pg.Generator();

    cout << "Prime (p): " << p << endl;
    cout << "Generator (g): " << g << endl;

    // Step 2: Generate private keys for both parties
    AutoSeededRandomPool rng;

    // Alice's private key (a)
    Integer a(rng, 128);
    // Bob's private key (b)
    Integer b(rng, 128);

    // Step 3: Calculate public keys
    // Alice's public key: A = g^a mod p
    Integer A = a_exp_b_mod_c(g, a, p);
    // Bob's public key: B = g^b mod p
    Integer B = a_exp_b_mod_c(g, b, p);

    cout << "Alice's Public Key (A): " << A << endl;
    cout << "Bob's Public Key (B): " << B << endl;

    // Step 4: Calculate the shared secret key
    // Alice calculates shared key: K_A = B^a mod p
    Integer K_A = a_exp_b_mod_c(B, a, p);
    // Bob calculates shared key: K_B = A^b mod p
    Integer K_B = a_exp_b_mod_c(A, b, p);

    cout << "Shared Secret Key (Alice's view): " << K_A << endl;
    cout << "Shared Secret Key (Bob's view): " << K_B << endl;

    // Step 5: Generate 128-bit key from shared secret
    SecByteBlock key((const byte*)K_A.Encode().data(), 16);

    // Save the key to a binary file
    FileSink file("shared_key.bin");
    file.Put(key, key.size());

    cout << "128-bit key generated and saved as 'shared_key.bin'" << endl;

    return 0;
}