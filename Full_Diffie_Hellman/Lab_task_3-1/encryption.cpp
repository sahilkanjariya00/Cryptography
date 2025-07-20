#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>   // For exponentiation and GCD
#include <cryptopp/files.h>      // For reading/writing files
#include <cryptopp/hex.h>        // For hex encoding/decoding
#include <cryptopp/randpool.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

using namespace CryptoPP;
using namespace std;

int main() {
    AutoSeededRandomPool rng;

    // Step 1: Read the public key (p, g, h) from the file
    Integer p, g, h;
    FileSource pubFile("public_key.bin", true);
    p.BERDecode(pubFile);
    g.BERDecode(pubFile);
    h.BERDecode(pubFile);

    // Print the values of p, g, h to the terminal
    cout << "Public Key (p, g, h): " << endl;
    cout << "p: " << p << endl;
    cout << "g: " << g << endl;
    cout << "h: " << h << endl;

    Integer p_minus_1 = p - Integer::One();  // p-1 for coprime check

    // Step 2: Choose a random integer k such that 1 <= k <= p-1 and coprime with p-1
    Integer k;
    do {
        k.Randomize(rng, Integer::One(), p_minus_1);  // Random k
    } while (GCD(k, p_minus_1) != Integer::One());  // Ensure gcd(k, p-1) = 1

    // Step 3: Compute C1 = g^k mod p
    Integer C1 = a_exp_b_mod_c(g, k, p);

    // Step 4: Read the entire content of the "data.txt" file
    ifstream infile("data.txt");
    stringstream buffer;
    buffer << infile.rdbuf();  // Read the entire file into a stringstream
    string message = buffer.str();  // Get the entire file content as a string
    infile.close();

    // Convert the message string to an integer M
    Integer M((const byte*)message.data(), message.size());

    cout << "Message M: " << M << endl;

    // Step 5: Compute C2 = M * h^k mod p
    Integer hk = a_exp_b_mod_c(h, k, p);  // Compute h^k mod p
    cout << "h^k mod p: " << hk << endl;
    Integer C2 = (M * hk) % p;  // Compute C2

    // Output the computed ciphertext C1 and C2
    cout << "Ciphertext (C1, C2):" << endl;
    cout << "C1: " << C1 << endl;
    cout << "C2: " << C2 << endl;

    // Step 6: Store C1, C2 in a file
    FileSink cipherFile("ciphertext.bin", true);
    C1.DEREncode(cipherFile);
    C2.DEREncode(cipherFile);
    cipherFile.MessageEnd();

    // Store k (private key) in a file
    FileSink kFile("k_private.bin", true);
    k.DEREncode(kFile);
    kFile.MessageEnd();

    cout << "Encryption complete. Ciphertext and k have been saved to files." << endl;

    return 0;
}


