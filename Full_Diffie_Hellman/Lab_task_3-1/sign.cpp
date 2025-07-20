#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>   // For modular arithmetic
#include <cryptopp/files.h>      // For file I/O
#include <cryptopp/hex.h>        // For hex encoding/decoding
#include <iostream>
#include <fstream>
#include <sstream>               // For reading entire file

using namespace CryptoPP;
using namespace std;

int main() {
    AutoSeededRandomPool rng;

    // Step 1: Read the public key (g, p) from the public_key.bin file
    Integer g, p;
    FileSource pubFile("public_key.bin", true);
    p.BERDecode(pubFile);
    g.BERDecode(pubFile);

    // Print the values of g and p
    cout << "Public Key (g, p):" << endl;
    cout << "g: " << g << endl;
    cout << "p: " << p << endl;

    // Step 2: Read the private key (x) from the private_key.bin file
    Integer x;
    FileSource privFile("private_key.bin", true);
    x.BERDecode(privFile);

    // Print the value of the private key x
    cout << "Private Key x: " << x << endl;

    // Step 3: Select a random integer r such that 1 <= r <= p-2 and r is coprime with (p-1)
    Integer p_minus_1 = p - Integer::One();  // p - 1
    Integer p_minus_2 = p_minus_1 - Integer::One();  // p - 1
    Integer r;
    do {
        r.Randomize(rng, Integer::Two(), p_minus_2);  // Random value r from Z(p-1)*
    } while (GCD(r, p_minus_2) != Integer::One());   // Ensure r is coprime with p-1

    // Print the value of r (sigma1)
    cout << "Private Key r (sigma1): " << r << endl;

    // Step 4: Read the entire message from the "data.txt" file
    ifstream infile("data.txt");
    stringstream buffer;
    buffer << infile.rdbuf();  // Read entire file content into a stringstream
    string message = buffer.str();
    infile.close();

    // Convert the message string to an integer M
    Integer m((const byte*)message.data(), message.size());

    cout << "Message M: " << m << endl;

    // Calculate r inverse mod (p-1)
    Integer r_inv = r.InverseMod(p_minus_1);

    // Calculate sigma2 = ((m - x * sigma1) * r_inv) mod (p-1)
    Integer sigma1 = r;
    Integer sigma2 = ((m - (x * sigma1)) * r_inv) % p_minus_1;

    // Print the value of sigma2
    cout << "Signature sigma2: " << sigma2 << endl;

    // Step 5: Save sigma1 and sigma2 as the signature
    FileSink sigFile("signature.bin", true);
    sigma1.DEREncode(sigFile);  // Save sigma1
    sigma2.DEREncode(sigFile);  // Save sigma2
    sigFile.MessageEnd();

    cout << "Digital signature (sigma1, sigma2) saved in 'signature.bin'." << endl;

    return 0;
}


