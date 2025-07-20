#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>   // For MaurerProvablePrime()
#include <cryptopp/files.h>
#include <cryptopp/dh.h>
#include <cryptopp/hex.h>
#include <cryptopp/randpool.h>
#include <cryptopp/algparam.h>
#include <cryptopp/pssr.h>
#include <iostream>

using namespace CryptoPP;
using namespace std;

// Function to check if g is a generator for prime p
bool IsGenerator(const Integer& g, const Integer& p) {
    // We need to ensure g^((p-1)/2) mod p != 1 for it to be a generator
    Integer p_minus_1 = p - Integer::One();
    Integer exp = p_minus_1 / Integer::Two();
    return a_exp_b_mod_c(g, exp, p) != Integer::One();
}

int main() {
    AutoSeededRandomPool rng;

    // Step 1: Generate a large prime number p (1024 bits)
    Integer p = MaurerProvablePrime(rng, 1024);  // Generates a prime of 1024 bits
    Integer p_minus_1 = p - Integer::One();

    // Step 2: Select generator g manually
    Integer g;
    do {
        g.Randomize(rng, Integer::Two(), p_minus_1);  // Random generator candidate
    } while (!IsGenerator(g, p));  // Ensure it's a valid generator

    // Step 3: Select private key x such that 1 <= x <= p-1 and gcd(x, p-1) = 1
    Integer x;
    do {
        x.Randomize(rng, Integer::One(), p_minus_1);  // Generate x
    } while (GCD(x, p_minus_1) != Integer::One());  // Ensure gcd(x, p-1) = 1

    // Step 4: Compute public key h = g^x mod p
    Integer h = a_exp_b_mod_c(g, x, p);  // Public key

    // Output the generated keys
    cout << "Public Key (p, g, h): " << endl;
    cout << "p: " << p << endl;
    cout << "g: " << g << endl;
    cout << "h: " << h << endl;
    cout << "Private Key x: " << x << endl;

    // Save public key (p, g, h) to a binary file
    FileSink pubFile("public_key.bin", true);
    p.DEREncode(pubFile);
    g.DEREncode(pubFile);
    h.DEREncode(pubFile);
    pubFile.MessageEnd();

    // Save private key (x) to a binary file
    FileSink privFile("private_key.bin", true);
    x.DEREncode(privFile);
    privFile.MessageEnd();

    cout << "Keys have been generated and saved to binary files." << endl;

    return 0;
}
