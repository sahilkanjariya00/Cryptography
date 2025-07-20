#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/files.h>
#include <cryptopp/dh.h>
#include <cryptopp/hex.h>
#include <cryptopp/randpool.h>
#include <cryptopp/algparam.h>
#include <cryptopp/pssr.h>
#include <iostream>

using namespace CryptoPP;
using namespace std;

int main() {
    AutoSeededRandomPool rng;

    // Step 1: Generate large prime p and generator g
    PrimeAndGenerator pg;
    cout<<"before generator\n";
    pg.Generate(1, rng, 1024, 1024);  // Generates a 1024-bit prime
    cout<<"before prime\n";
    Integer p = pg.Prime();           // Prime number p
    cout<<"after prime\n";
    Integer g = pg.Generator();       // Generator g
    Integer p_minus_1 = p - Integer::One();  // p-1 for coprime check

    // Step 2: Select private key x such that 1 <= x <= p-1 and gcd(x, p-1) = 1
    Integer x;
    do {
        x.Randomize(rng, Integer::One(), p_minus_1);  // Generate x
    } while (GCD(x, p_minus_1) != Integer::One());  // Ensure gcd(x, p-1) = 1

    // Step 3: Compute public key h = g^x mod p
    Integer h = a_exp_b_mod_c(g, x, p);  // Public key

    // Output the generated keys
    cout << "Public Key (p, g, h): " << endl;
    cout << "p: " << p << endl;
    cout << "g: " << g << endl;
    cout << "h: " << h << endl;
    cout << "Private Key x: " << x << endl;

    // Step 4: Save public key (p, g, h) to a binary file
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
