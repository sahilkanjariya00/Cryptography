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

// Function to read ciphertext from file
void ReadCipher(Integer& c1, Integer& c2, const string& filename) {
    FileSource inFile(filename.c_str(), true);
    c1.BERDecode(inFile);
    c2.BERDecode(inFile);
}

// Function to compute GCD and coefficients for Extended Euclidean Algorithm
Integer ExtendedGCD(const Integer& a, const Integer& b, Integer& x, Integer& y) {
    if (b == 0) {
        x = Integer::One();
        y = Integer::Zero();
        return a;
    }

    Integer x1, y1;
    Integer gcd = ExtendedGCD(b, a % b, x1, y1);
    
    x = y1;
    y = x1 - (a / b) * y1;
    
    return gcd;
}

// Function to compute modular inverse
Integer ModInverse(const Integer& a, const Integer& m) {
    Integer x, y;
    Integer g = ExtendedGCD(a, m, x, y);
    if (g != 1) throw runtime_error("Inverse doesn't exist");
    return (x % m + m) % m; // Ensure the result is positive
}

// Function to convert Integer to string
string IntegerToString(const Integer& m) {
    // Get byte array size
    size_t size = m.ByteCount();
    byte* buffer = new byte[size];
    m.Encode(buffer, size);
    
    // Create string from byte array
    string result((const char*)buffer, size);
    delete[] buffer; // Clean up dynamically allocated memory
    return result;
}

int main() {
    Integer u, g, p;

    // Read public keys from file
    FileSource pubFile("public_key.bin", true);
    p.BERDecode(pubFile);
    g.BERDecode(pubFile);
    u.BERDecode(pubFile);

    // Read private key from a file (you should have saved this during key generation)
    Integer x; // Your private key
    FileSource privKeyFile("private_key.bin", true); // Adjust filename as needed
    x.BERDecode(privKeyFile);

    // Read the ciphertext
    Integer c1, c2;
    ReadCipher(c1, c2, "cipher.bin");
    
    // Compute shared secret: s = c1^x mod p
    Integer s = a_exp_b_mod_c(c1, x, p);
    // Compute the modular inverse of s
    Integer s_inv = ModInverse(s, p);
    // Recover the original message: m = (c2 * s_inv) mod p
    Integer m = (c2 * s_inv) % p;

    
    // Convert the recovered message back to a string
    string recoveredMessage = IntegerToString(m);
    // Save the recovered message to recover.txt
    ofstream outfile("recover.txt");
    if (outfile.is_open()) {
        outfile << recoveredMessage;
        outfile.close();
        cout << "Recovered message has been saved to recover.txt." << endl;
    } else {
        cerr << "Error opening recover.txt for writing." << endl;
    }

    return 0;
}
