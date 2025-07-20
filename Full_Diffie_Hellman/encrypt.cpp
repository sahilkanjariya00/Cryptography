#include <iostream>
#include <fstream>
#include <sstream>
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/dh.h>
#include <cryptopp/integer.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;
using namespace std;

void StoreCipher(const Integer& c1, const Integer& c2, const std::string& filename) {
    // Use CryptoPP's FileSink instead of std::ofstream
    FileSink outFile(filename.c_str(), true); // true for overwrite
    c1.DEREncode(outFile);
    c2.DEREncode(outFile);
}

int main() {
    Integer u, g, p;

    // Read public keys from file
    FileSource pubFile("public_key.bin", true);
    p.BERDecode(pubFile);
    g.BERDecode(pubFile);
    u.BERDecode(pubFile);

    // Read the message from the data file
    ifstream infile("data.txt");
    stringstream buffer;
    buffer << infile.rdbuf();  // Read the entire file into a stringstream
    string message = buffer.str();  // Get the entire file content as a string
    infile.close();
    Integer m((const byte*)message.data(), message.size());

    Integer r, c1, c2;
    AutoSeededRandomPool rng;
    r.Randomize(rng, 2, p-1);  // Generate random r
    c1 = a_exp_b_mod_c(g, r, p);  // Compute c1 = g^r mod p
    c2 = (a_exp_b_mod_c(m, 1, p) * a_exp_b_mod_c(u, r, p)) % p;  // Compute c2

    // Store ciphertext
    StoreCipher(c1, c2, "cipher.bin");

    return 0;
}
